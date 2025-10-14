#!/usr/bin/env python3
#!/usr/bin/env python3
"""
GraphQL Endpoint Enumeration Engine v2
Author: Hussein Habashi Style ⚔️
"""

import aiohttp
import asyncio
import re
import time
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any

class EndpointEnumerator:
    def __init__(self, base_url: str, wordlist: str = None, concurrency: int = 20, verbose: bool = True):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist
        self.verbose = verbose
        self.concurrency = concurrency
        self.session = None

    async def enumerate_endpoints(self) -> List[Dict[str, Any]]:
        print("[*] Starting GraphQL endpoint enumeration...")
        all_endpoints = set()

        async with aiohttp.ClientSession() as session:
            self.session = session

            techniques = [
                self._common_path_enumeration(),
                self._passive_discovery(),
                self._wordlist_bruteforce()
            ]

            results = await asyncio.gather(*techniques, return_exceptions=True)
            for result in results:
                if result:
                    all_endpoints.update(result)

            print(f"[*] Discovered {len(all_endpoints)} potential endpoints. Testing them...")

            endpoints_info = await self._test_endpoints(list(all_endpoints))
            return endpoints_info

    # ===============================================================
    # 📍 Technique 1: Common path brute-force
    # ===============================================================
    async def _common_path_enumeration(self) -> List[str]:
        paths = [
            '/graphql', '/api/graphql', '/gql', '/query', '/api',
            '/v1/graphql', '/v2/graphql', '/v3/graphql', '/graphql-api',
            '/graphql/console', '/admin/graphql', '/internal/graphql',
            '/hasura/v1/graphql', '/graphql/v1', '/graphql/v2',
            '/api/v1/graphql', '/api/v2/graphql', '/backend/graphql',
            '/public/graphql', '/private/graphql', '/core/graphql'
        ]
        return [urljoin(self.base_url, p) for p in paths]

    # ===============================================================
    # 📜 Technique 2: Passive discovery (homepage, robots, sitemap)
    # ===============================================================
    async def _passive_discovery(self) -> List[str]:
        paths = []
        endpoints_to_check = ['', '/robots.txt', '/sitemap.xml']
        for path in endpoints_to_check:
            url = urljoin(self.base_url, path)
            try:
                async with self.session.get(url, timeout=8) as r:
                    text = await r.text()
                    found = re.findall(r'(/[a-zA-Z0-9_\-\/]*graphql[a-zA-Z0-9_\-\/]*)', text)
                    for match in found:
                        paths.append(urljoin(self.base_url, match))
            except:
                continue
        return paths

    # ===============================================================
    # 📂 Technique 3: Wordlist brute-force (optional)
    # ===============================================================
    async def _wordlist_bruteforce(self) -> List[str]:
        if not self.wordlist:
            return []
        endpoints = []
        try:
            with open(self.wordlist, 'r') as f:
                for line in f:
                    path = line.strip()
                    if path:
                        endpoints.append(urljoin(self.base_url, path if path.startswith('/') else '/' + path))
        except:
            pass
        return endpoints

    # ===============================================================
    # 🧪 Test discovered endpoints
    # ===============================================================
    async def _test_endpoints(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._test_single_endpoint(ep, sem) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r and isinstance(r, dict)]

    async def _test_single_endpoint(self, endpoint: str, sem: asyncio.Semaphore) -> Dict[str, Any]:
        async with sem:
            result = {
                "url": endpoint,
                "status": None,
                "is_graphql": False,
                "introspection_enabled": False,
                "implementation": "unknown",
                "response_time_ms": None,
                "confidence": 0
            }

            try:
                test_query = {"query": "query { __typename }"}
                start = time.time()
                async with self.session.post(endpoint, json=test_query, timeout=10) as r:
                    result["status"] = r.status
                    result["response_time_ms"] = int((time.time() - start) * 1000)
                    text = await r.text()

                    # Check if endpoint behaves like GraphQL
                    if "__typename" in text or "Cannot query field" in text:
                        result["is_graphql"] = True
                        result["confidence"] = 70

                    # Introspection test
                    introspection_query = {"query": "query { __schema { types { name } } }"}
                    async with self.session.post(endpoint, json=introspection_query, timeout=10) as r2:
                        introspection_text = await r2.text()
                        if "__schema" in introspection_text:
                            result["introspection_enabled"] = True
                            result["confidence"] = 100

                    # Try to fingerprint implementation from headers or body
                    headers = {k.lower(): v for k, v in r.headers.items()}
                    if any("apollo" in v.lower() for v in headers.values()):
                        result["implementation"] = "Apollo Server"
                    elif "hasura" in text.lower():
                        result["implementation"] = "Hasura"
                    elif "appsync" in text.lower():
                        result["implementation"] = "AWS AppSync"

            except Exception:
                pass

            return result if result["is_graphql"] else None

# 🧪 CLI usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 graphql_endpoints.py <base_url> [wordlist.txt]")
        sys.exit(1)

    base_url = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) == 3 else None

    enumerator = EndpointEnumerator(base_url, wordlist=wordlist)
    endpoints = asyncio.run(enumerator.enumerate_endpoints())
    print("\n[✓] Enumeration complete. Discovered endpoints:\n")
    for ep in endpoints:
        print(json.dumps(ep, indent=2))