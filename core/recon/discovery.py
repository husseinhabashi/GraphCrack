#!/usr/bin/env python3
"""
Advanced GraphQL Endpoint Discovery
"""

import aiohttp
import asyncio
from urllib.parse import urljoin
import json
import re

class GraphQLDiscoverer:
    def __init__(self, base_url, wordlist=None, concurrency=20, verbose=True):
        self.base_url = base_url.rstrip('/')
        self.session = None
        self.verbose = verbose
        self.semaphore = asyncio.Semaphore(concurrency)
        
        # Core + extended common paths
        self.common_paths = [
            '/graphql', '/api/graphql', '/gql', '/query', '/graphql/query',
            '/api', '/v1/graphql', '/v2/graphql', '/graphql-api', '/graphql/console',
            '/admin/graphql', '/internal/graphql', '/backend/graphql', '/core/graphql',
            '/public/graphql', '/private/graphql', '/graph', '/graphql/endpoint',
            '/graphql/playground', '/graphql/explorer', '/graphql-service'
        ]

        # Add extra wordlist if provided
        if wordlist:
            with open(wordlist) as f:
                self.common_paths.extend([line.strip() for line in f if line.strip()])

    async def discover_endpoints(self):
        endpoints = []
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Optional: grab hints from robots.txt, sitemap, and homepage
            hinted_paths = await self.scan_for_hints()
            all_paths = list(set(self.common_paths + hinted_paths))
            
            tasks = [self.test_graphql_endpoint(urljoin(self.base_url, path)) for path in all_paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for url, is_graphql in zip([urljoin(self.base_url, p) for p in all_paths], results):
                if is_graphql:
                    endpoints.append(url)
                    if self.verbose:
                        print(f"[+] GraphQL endpoint found: {url}")

        return endpoints

    async def test_graphql_endpoint(self, url):
        async with self.semaphore:
            try:
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Requested-With": "XMLHttpRequest"
                }

                test_queries = [
                    {"query": "query { __typename }"},  # lightweight
                    {"query": "query { __schema { types { name } } }"},  # introspection
                    {"query": "query { invalidField }"}  # error test
                ]

                for payload in test_queries:
                    async with self.session.post(url, json=payload, headers=headers, timeout=8) as response:
                        text = await response.text()
                        content_type = response.headers.get("Content-Type", "")
                        
                        # Try parse JSON if possible
                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            data = {}

                        # GraphQL indicators
                        if self.is_graphql_response(data) or self.is_graphql_like(text, content_type):
                            if self.verbose:
                                print(f"    └─ [Detected GraphQL at {url}] ({response.status})")
                            return True
            except Exception:
                return False
        return False

    def is_graphql_response(self, data):
        if isinstance(data, dict):
            if 'data' in data or 'errors' in data:
                return True
        return False

    def is_graphql_like(self, text, content_type):
        # Looser detection when introspection is disabled
        graphql_keywords = ['Cannot query field', 'GraphQL', '__schema', 'syntax error', 'must be a query root']
        if any(k.lower() in text.lower() for k in graphql_keywords):
            return True
        if 'application/json' in content_type and re.search(r'"errors":\s*\[', text):
            return True
        return False

    async def scan_for_hints(self):
        """Scrape homepage, robots.txt, sitemap.xml for GraphQL clues"""
        hinted_paths = []
        potential_files = ['', '/robots.txt', '/sitemap.xml']
        async with aiohttp.ClientSession() as session:
            for path in potential_files:
                url = urljoin(self.base_url, path)
                try:
                    async with session.get(url, timeout=5) as resp:
                        text = await resp.text()
                        found = re.findall(r'(\/[a-zA-Z0-9_\-\/]*graphql[a-zA-Z0-9_\-\/]*)', text)
                        hinted_paths.extend(found)
                except:
                    continue
        return hinted_paths

# Example usage
if __name__ == "__main__":
    target = "https://example.com"
    discoverer = GraphQLDiscoverer(target, concurrency=30, verbose=True)
    endpoints = asyncio.run(discoverer.discover_endpoints())
    print("\n[✓] Discovered endpoints:")
    for ep in endpoints:
        print("   →", ep)