#!/usr/bin/env python3
"""
GraphQL Client Utilities for making requests (Offensive Edition)
Handles async requests, retries, introspection, and stealth mode for GraphCrack Engine.
"""

import aiohttp
import asyncio
import json
import random
import time
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager

# ────────────────────────────────────────────────
#  Core GraphQL Client
# ────────────────────────────────────────────────
class GraphQLClient:
    def __init__(self, endpoint: str, headers: Optional[Dict[str, str]] = None, timeout: int = 10, proxy: Optional[str] = None):
        self.endpoint = endpoint
        self.timeout = timeout
        self.proxy = proxy
        self.session = None
        self.headers = headers or self._default_headers()

    # ────────────────────────────────────────────────
    #  Context Manager
    # ────────────────────────────────────────────────
    async def __aenter__(self):
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(headers=self.headers, timeout=timeout_obj)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    # ────────────────────────────────────────────────
    #  Query Execution
    # ────────────────────────────────────────────────
    async def execute_query(self, query: str, variables: Optional[Dict[str, Any]] = None, operation_name: Optional[str] = None, retries: int = 2) -> Dict[str, Any]:
        """Execute a GraphQL query with retry and detection logic"""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name

        attempt = 0
        start_time = time.time()
        while attempt <= retries:
            try:
                async with self.session.post(self.endpoint, json=payload, proxy=self.proxy) as response:
                    latency = round(time.time() - start_time, 3)
                    text = await response.text()
                    result = {"status": response.status, "latency": latency, "size": len(text)}

                    # Parse response safely
                    try:
                        result["data"] = json.loads(text)
                    except json.JSONDecodeError:
                        result["data"] = {"errors": [{"message": "Malformed JSON response", "raw": text}]}

                    # Check for GraphQL indicators
                    result["is_graphql"] = "data" in result["data"] or "errors" in result["data"]

                    # Detect rate limiting / blocking
                    waf_flags = ["blocked", "captcha", "access denied", "403", "firewall"]
                    if any(flag in text.lower() for flag in waf_flags):
                        result["waf_detected"] = True

                    return result
            except aiohttp.ClientError as e:
                attempt += 1
                await asyncio.sleep(1 + attempt * 0.5)
                if attempt > retries:
                    return {"errors": [{"message": f"Request failed after {retries} retries: {e}"}]}

        return {"errors": [{"message": "Failed to connect to endpoint"}]}

    # ────────────────────────────────────────────────
    #  Introspection Query
    # ────────────────────────────────────────────────
    async def execute_introspection(self) -> Dict[str, Any]:
        """Perform a full introspection query"""
        introspection_query = """
        query {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name kind description
              fields(includeDeprecated: true) { name description }
            }
          }
        }
        """
        response = await self.execute_query(introspection_query)
        if response.get("data") and "data" in response["data"]:
            response["introspection_enabled"] = True
        else:
            response["introspection_enabled"] = False
        return response

    # ────────────────────────────────────────────────
    #  Batch Requests
    # ────────────────────────────────────────────────
    async def execute_batch(self, queries: List[Dict[str, Any]], concurrency: int = 5) -> List[Dict[str, Any]]:
        """Send multiple GraphQL queries concurrently (with rate limiting)"""
        semaphore = asyncio.Semaphore(concurrency)
        results = []

        async def _run_query(q):
            async with semaphore:
                return await self.execute_query(**q)

        tasks = [_run_query(q) for q in queries]
        for future in asyncio.as_completed(tasks):
            try:
                results.append(await future)
            except Exception as e:
                results.append({"error": str(e)})

        return results

    # ────────────────────────────────────────────────
    #  Endpoint Testing
    # ────────────────────────────────────────────────
    async def test_endpoint(self) -> Dict[str, Any]:
        """Probe GraphQL endpoint for introspection & response behavior"""
        test_payload = {"query": "query { __typename }"}
        result = await self.execute_query(**test_payload)

        return {
            "endpoint": self.endpoint,
            "reachable": "data" in result.get("data", {}),
            "graphql_detected": result.get("is_graphql", False),
            "introspection_enabled": await self._test_introspection_short(),
            "latency": result.get("latency"),
            "status": result.get("status"),
        }

    async def _test_introspection_short(self) -> bool:
        """Lightweight introspection probe"""
        query = {"query": "query { __schema { queryType { name } } }"}
        result = await self.execute_query(**query)
        data = result.get("data", {})
        return "data" in data and "__schema" in str(data)

    # ────────────────────────────────────────────────
    #  Default Headers & Randomization
    # ────────────────────────────────────────────────
    def _default_headers(self) -> Dict[str, str]:
        """Return a randomized, legitimate client header set"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "GraphQL Playground/1.7.8",
            "Insomnia/2024.2.0",
            "ApolloClient/3.8.0"
        ]
        return {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "User-Agent": random.choice(user_agents),
            "Origin": f"https://{self.endpoint.split('/')[2]}",
            "Referer": self.endpoint
        }

    # ────────────────────────────────────────────────
    #  Utility
    # ────────────────────────────────────────────────
    async def close(self):
        """Manually close session"""
        if self.session:
            await self.session.close()


# ────────────────────────────────────────────────
#  CLI Testing Mode
# ────────────────────────────────────────────────
if __name__ == "__main__":
    async def main():
        import sys
        if len(sys.argv) < 2:
            print("Usage: python graphql_client.py <endpoint>")
            return
        url = sys.argv[1]
        async with GraphQLClient(url) as client:
            print(f"[*] Testing GraphQL endpoint: {url}")
            info = await client.test_endpoint()
            print(json.dumps(info, indent=2))

    asyncio.run(main())