#!/usr/bin/env python3
"""
GraphQL Introspection & Security Analysis Engine
"""

import aiohttp
import asyncio
import json
import re
from typing import Dict, Any, List

class IntrospectionAnalyzer:
    def __init__(self, endpoint_url: str, verbose: bool = True):
        self.endpoint_url = endpoint_url.rstrip("/")
        self.verbose = verbose
        self.session = None

    async def run(self) -> Dict[str, Any]:
        """Main entrypoint: perform introspection and analyze it."""
        schema = await self.get_introspection()
        if not schema:
            return {"introspection_enabled": False, "recommendation": "Introspection disabled — attempt error-based schema leak."}

        analysis = self.analyze_schema(schema)
        analysis["introspection_enabled"] = True
        return analysis

    # =======================================================
    # 🧪 Step 1: Pull the full introspection schema (fallback-aware)
    # =======================================================
    async def get_introspection(self) -> Dict[str, Any]:
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types { ...FullType }
            directives {
              name description locations args { ...InputValue }
            }
          }
        }
        fragment FullType on __Type {
          kind name description
          fields(includeDeprecated: true) {
            name description args { ...InputValue }
            type { ...TypeRef } isDeprecated deprecationReason
          }
          inputFields { ...InputValue }
          interfaces { ...TypeRef }
          enumValues(includeDeprecated: true) {
            name description isDeprecated deprecationReason
          }
          possibleTypes { ...TypeRef }
        }
        fragment InputValue on __InputValue {
          name description type { ...TypeRef } defaultValue
        }
        fragment TypeRef on __Type {
          kind name ofType {
            kind name ofType {
              kind name ofType {
                kind name ofType {
                  kind name
                }
              }
            }
          }
        }
        """

        try:
            async with aiohttp.ClientSession() as session:
                self.session = session
                payload = {"query": introspection_query}
                async with session.post(self.endpoint_url, json=payload, timeout=30) as response:
                    text = await response.text()
                    if response.status == 200:
                        data = json.loads(text)
                        if "data" in data and "__schema" in data["data"]:
                            return data["data"]
        except Exception as e:
            if self.verbose:
                print(f"[!] Introspection failed: {e}")
        return None

    # =======================================================
    # 🧠 Step 2: Analyze the schema for juicy targets
    # =======================================================
    def analyze_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        report = {
            "sensitive_queries": [],
            "sensitive_mutations": [],
            "authentication_flows": [],
            "risky_directives": [],
            "data_exposure": [],
            "deprecated_fields": [],
            "possible_injection_points": []
        }

        types = schema.get("__schema", {}).get("types", [])
        for t in types:
            type_name = t.get("name", "")
            if type_name.startswith("__"):  # skip introspection internals
                continue

            fields = t.get("fields", []) or []
            for field in fields:
                field_name = field.get("name", "")
                field_desc = (field.get("description") or "").lower()
                args = field.get("args", []) or []

                # 1. Sensitive Data Exposure
                if self._is_sensitive_field(field_name, field_desc):
                    report["sensitive_queries"].append(self._make_entry(type_name, field_name, field_desc, severity="High"))

                # 2. Authentication Flows
                if self._is_auth_field(field_name, field_desc):
                    report["authentication_flows"].append(self._make_entry(type_name, field_name, field_desc, severity="High"))

                # 3. Dangerous Mutations
                if t.get("kind") == "OBJECT" and "Mutation" in type_name and self._is_dangerous_mutation(field_name):
                    report["sensitive_mutations"].append(self._make_entry(type_name, field_name, field_desc, severity="Critical"))

                # 4. Deprecated but Present Fields
                if field.get("isDeprecated"):
                    report["deprecated_fields"].append(self._make_entry(type_name, field_name, field_desc, severity="Medium"))

                # 5. Potential Injection Points
                for arg in args:
                    arg_name = arg.get("name", "")
                    arg_type = self._flatten_type(arg.get("type", {}))
                    if self._is_injection_candidate(arg_name, arg_type):
                        report["possible_injection_points"].append({
                            "type": type_name,
                            "field": field_name,
                            "argument": arg_name,
                            "arg_type": arg_type,
                            "severity": "Medium"
                        })

                # 6. Default values leakage
                for arg in args:
                    default_val = arg.get("defaultValue")
                    if default_val and any(keyword in str(default_val).lower() for keyword in ["key", "secret", "token"]):
                        report["data_exposure"].append({
                            "type": type_name,
                            "field": field_name,
                            "leak": default_val,
                            "severity": "High"
                        })

        return report

    # =======================================================
    # 🧪 Detection Logic
    # =======================================================
    def _is_sensitive_field(self, name, desc):
        keywords = ["user", "admin", "password", "token", "secret", "key", "credential", "role", "account", "email", "phone", "ssn", "credit"]
        return any(k in name.lower() or k in desc for k in keywords)

    def _is_auth_field(self, name, desc):
        keywords = ["login", "auth", "authenticate", "jwt", "session", "signin", "signup", "register", "oauth"]
        return any(k in name.lower() or k in desc for k in keywords)

    def _is_dangerous_mutation(self, field):
        dangerous_ops = ["delete", "drop", "createAdmin", "reset", "truncate", "execute"]
        return any(op in field.lower() for op in dangerous_ops)

    def _is_injection_candidate(self, arg_name, arg_type):
        if not arg_type:
            return False
        arg_keywords = ["query", "where", "filter", "search", "command", "expression"]
        type_keywords = ["String", "ID", "JSON", "Upload"]
        return any(k in arg_name.lower() for k in arg_keywords) and any(t in arg_type for t in type_keywords)

    def _flatten_type(self, t):
        if not isinstance(t, dict):
            return ""
        base = t.get("name") or ""
        oftype = self._flatten_type(t.get("ofType")) if t.get("ofType") else ""
        return base + (" -> " + oftype if oftype else "")

    def _make_entry(self, type_name, field_name, description, severity):
        return {
            "type": type_name,
            "field": field_name,
            "description": description,
            "severity": severity
        }


# 🧪 CLI Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 graphql_introspect.py <endpoint_url>")
        sys.exit(1)

    url = sys.argv[1]
    analyzer = IntrospectionAnalyzer(url)
    result = asyncio.run(analyzer.run())
    print(json.dumps(result, indent=2))