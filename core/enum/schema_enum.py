#!/usr/bin/env python3
"""
GraphQL Schema Enumeration Engine – Final Version
"""

import aiohttp
import asyncio
import json
import re
from typing import Dict, Any, List


class SchemaEnumerator:
    def __init__(self, endpoint_url: str, wordlist: str = None, verbose: bool = True):
        self.endpoint_url = endpoint_url.rstrip("/")
        self.wordlist = wordlist
        self.verbose = verbose
        self.session = None
        self.schema_map = {
            "queries": {},
            "mutations": {},
            "subscriptions": {},
            "types": {},
            "relationships": {},
            "sensitive_operations": []
        }

    async def enumerate_schema(self) -> Dict[str, Any]:
        print("[*] Starting advanced schema enumeration...")

        async with aiohttp.ClientSession() as session:
            self.session = session

            techniques = [
                self._root_type_discovery(),
                self._error_based_enumeration(),
                self._keyword_spray_enumeration()
            ]

            results = await asyncio.gather(*techniques, return_exceptions=True)
            for r in results:
                if r and isinstance(r, dict):
                    self._merge_schema(r)

        # ✅ FIXED: call correct detection method
        self.schema_map["sensitive_operations"] = self.detect_sensitive_operations()
        return self.schema_map

    # ======================================================
    # 🧬 Technique 1 – Root type discovery
    # ======================================================
    async def _root_type_discovery(self) -> Dict[str, Any]:
        results = {"queries": {}, "mutations": {}, "subscriptions": {}, "types": {}}
        query = {"query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }"}

        try:
            async with self.session.post(self.endpoint_url, json=query, timeout=10) as r:
                data = await r.json()
                schema = data.get("data", {}).get("__schema", {})
                for t in ["queryType", "mutationType", "subscriptionType"]:
                    if schema.get(t):
                        results[t.replace("Type", "s")][schema[t]["name"]] = {"confidence": 100}
        except Exception:
            pass

        return results

    # ======================================================
    # 🧪 Technique 2 – Error-based schema enumeration
    # ======================================================
    async def _error_based_enumeration(self) -> Dict[str, Any]:
        results = {"queries": {}, "mutations": {}, "types": {}}
        fake_fields = ["idontexist123", "fakeQuery", "randomTest"]

        for f in fake_fields:
            payload = {"query": f"query {{ {f} }}"}
            try:
                async with self.session.post(self.endpoint_url, json=payload, timeout=6) as r:
                    text = await r.text()
                    matches = re.findall(r'Cannot query field "(.*?)"', text)
                    for m in matches:
                        results["queries"][m] = {"confidence": 50}
            except Exception:
                continue
        return results

    # ======================================================
    # 🚀 Technique 3 – Keyword spraying (wordlist-based)
    # ======================================================
    async def _keyword_spray_enumeration(self) -> Dict[str, Any]:
        results = {"queries": {}}
        candidates = self._load_wordlist()

        tasks = [self._test_field(field) for field in candidates]

        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        for field, ok in zip(candidates, results_list):
            if ok:
                results["queries"][field] = {"confidence": 70}
        return results

    async def _test_field(self, field: str) -> bool:
        payload = {"query": f"query {{ {field} {{ __typename }} }}"}
        try:
            async with self.session.post(self.endpoint_url, json=payload, timeout=6) as r:
                text = await r.text()
                return "Cannot query field" not in text
        except Exception:
            return False

    # ======================================================
    # 🧠 Sensitive operation detection (✅ fixed indentation)
    # ======================================================
    def detect_sensitive_operations(self, schema=None) -> List[Dict[str, Any]]:
        """Identify sensitive operations from the discovered schema."""
        if schema is None:
            schema = self.schema_map

        sensitive_ops = []
        keywords = {
            "auth": ["auth", "login", "signup", "register", "session", "jwt", "token"],
            "info_disclosure": ["user", "email", "password", "admin", "key", "secret", "credential"],
            "dangerous_mutations": ["delete", "drop", "remove", "truncate", "createAdmin", "updatePassword"]
        }

        for q in schema.get("queries", {}).keys():
            for cat, kw_list in keywords.items():
                if any(kw in q.lower() for kw in kw_list):
                    sensitive_ops.append({
                        "operation": q,
                        "risk": cat,
                        "severity": self._map_severity(cat)
                    })

        return sensitive_ops

    def _map_severity(self, risk_type: str) -> str:
        return {
            "auth": "HIGH",
            "info_disclosure": "MEDIUM",
            "dangerous_mutations": "CRITICAL"
        }.get(risk_type, "LOW")

    # ======================================================
    # 📁 Helpers
    # ======================================================
    def _load_wordlist(self) -> List[str]:
        base = [
            "user", "users", "me", "profile", "admin", "auth", "login",
            "resetPassword", "refreshToken", "products", "orders", "customers",
            "team", "members", "organization", "session", "roles", "permissions"
        ]
        if self.wordlist:
            try:
                with open(self.wordlist, "r") as f:
                    base.extend([l.strip() for l in f if l.strip()])
            except Exception:
                pass
        return list(set(base))

    def _merge_schema(self, new_schema: Dict[str, Any]):
        for section in self.schema_map:
            if section == "sensitive_operations":
                continue
            self.schema_map[section].update(new_schema.get(section, {}))


# 🧪 CLI Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 graphql_schema_enum.py <endpoint_url> [wordlist.txt]")
        sys.exit(1)

    url = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) == 3 else None

    enumerator = SchemaEnumerator(url, wordlist=wordlist)
    result = asyncio.run(enumerator.enumerate_schema())
    print(json.dumps(result, indent=2))