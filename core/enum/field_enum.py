#!/usr/bin/env python3
"""
GraphQL Field Enumeration Engine v2
Author: Hussein Habashi Style ⚔️
"""

import aiohttp
import asyncio
import json
import re
from typing import Dict, Any, List, Set

class FieldEnumerator:
    def __init__(self, endpoint_url: str, wordlist: str = None, verbose: bool = True):
        self.endpoint_url = endpoint_url.rstrip("/")
        self.wordlist = wordlist
        self.verbose = verbose
        self.session = None
        self.discovered = {
            "queries": {},
            "mutations": {},
            "subscriptions": {},
            "types": {},
            "fields_by_type": {}
        }

    async def enumerate_fields(self) -> Dict[str, Any]:
        print("[*] Starting comprehensive field enumeration...")

        async with aiohttp.ClientSession() as session:
            self.session = session

            techniques = [
                self._introspection_enumeration(),
                self._error_leak_enumeration(),
                self._field_spray_enumeration()
            ]

            results = await asyncio.gather(*techniques, return_exceptions=True)

            for result in results:
                if result and isinstance(result, dict):
                    self._merge_results(result)

        return self.discovered

    # ================================================================
    # 🧬 Technique 1: Full or Partial Introspection Enumeration
    # ================================================================
    async def _introspection_enumeration(self) -> Dict[str, Any]:
        discoveries = self._empty_discovery()
        try:
            introspection_query = {"query": "query { __schema { types { name fields { name } } } }"}
            async with self.session.post(self.endpoint_url, json=introspection_query, timeout=20) as r:
                if r.status == 200:
                    data = await r.json()
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    for t in types:
                        t_name = t.get("name")
                        fields = t.get("fields", [])
                        discoveries["types"][t_name] = {"confidence": 100}
                        for f in fields:
                            fname = f.get("name")
                            discoveries["fields_by_type"].setdefault(t_name, []).append(fname)
                            # classify queries vs mutations
                            if "query" in t_name.lower():
                                discoveries["queries"][fname] = {"confidence": 100}
                            if "mutation" in t_name.lower():
                                discoveries["mutations"][fname] = {"confidence": 100}
        except Exception:
            pass
        return discoveries

    # ================================================================
    # 🧪 Technique 2: Error-Leak Enumeration (when introspection disabled)
    # ================================================================
    async def _error_leak_enumeration(self) -> Dict[str, Any]:
        discoveries = self._empty_discovery()
        test_field = "idontexist"
        payload = {"query": f"query {{ {test_field} }}"}

        try:
            async with self.session.post(self.endpoint_url, json=payload, timeout=10) as r:
                text = await r.text()
                matches = re.findall(r'Cannot query field "(.*?)"', text)
                for m in matches:
                    discoveries["queries"][m] = {"confidence": 50}
        except:
            pass
        return discoveries

    # ================================================================
    # 🔥 Technique 3: Field Spray Enumeration (brute-force)
    # ================================================================
    async def _field_spray_enumeration(self) -> Dict[str, Any]:
        discoveries = self._empty_discovery()
        candidates = self._load_common_fields()

        tasks = []
        for field in candidates:
            tasks.append(self._test_field(field))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for field, result in zip(candidates, results):
            if result:
                discoveries["queries"][field] = {"confidence": 70}

        return discoveries

    async def _test_field(self, field):
        payload = {"query": f"query {{ {field} {{ __typename }} }}"}
        try:
            async with self.session.post(self.endpoint_url, json=payload, timeout=6) as r:
                data = await r.text()
                return '"data"' in data or "Cannot query field" not in data
        except:
            return False

    # ================================================================
    # 🧰 Helpers
    # ================================================================
    def _load_common_fields(self) -> List[str]:
        base_fields = [
            "user", "users", "post", "posts", "me", "profile", "admin",
            "account", "orders", "settings", "config", "currentUser",
            "organization", "team", "members", "customers", "sessions",
            "auth", "verify", "resetPassword", "refreshToken"
        ]
        if self.wordlist:
            try:
                with open(self.wordlist) as f:
                    base_fields.extend([line.strip() for line in f if line.strip()])
            except:
                pass
        return list(set(base_fields))

    def _empty_discovery(self) -> Dict[str, Any]:
        return {
            "queries": {},
            "mutations": {},
            "subscriptions": {},
            "types": {},
            "fields_by_type": {}
        }

    def _merge_results(self, new: Dict[str, Any]):
        for category in self.discovered:
            if category == "fields_by_type":
                for t, fields in new.get("fields_by_type", {}).items():
                    self.discovered["fields_by_type"].setdefault(t, [])
                    self.discovered["fields_by_type"][t].extend(fields)
            else:
                self.discovered[category].update(new.get(category, {}))


# 🧪 CLI usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 graphql_enum.py <endpoint_url> [wordlist.txt]")
        sys.exit(1)

    url = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) == 3 else None
    enumerator = FieldEnumerator(url, wordlist=wordlist)
    result = asyncio.run(enumerator.enumerate_fields())
    print(json.dumps(result, indent=2))