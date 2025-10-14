#!/usr/bin/env python3
"""
GraphQL Fingerprinting Beast Mode
Author: Hussein Habashi style 🧠
"""

import aiohttp
import asyncio
import re
import json
from typing import Dict, Any, List

class GraphQLFingerprinter:
    def __init__(self, endpoint_url: str, verbose: bool = True):
        self.endpoint_url = endpoint_url.rstrip("/")
        self.session = None
        self.verbose = verbose

    async def fingerprint(self) -> Dict[str, Any]:
        results = {
            "implementation": "Unknown",
            "confidence": 0,
            "version": "Unknown",
            "headers": {},
            "features": [],
            "metadata": {},
            "vulnerabilities": []
        }

        async with aiohttp.ClientSession() as session:
            self.session = session

            # Fire all detection checks in parallel
            detections = await asyncio.gather(
                self._detect_implementations(),
                self._get_headers(),
                self._detect_features(),
                self._extract_metadata()
            )

            impl, headers, features, metadata = detections
            results.update(impl)
            results["headers"] = headers
            results["features"] = features
            results["metadata"] = metadata
            results["vulnerabilities"] = self._map_vulns(impl["implementation"], impl.get("version", ""))
        
        return results

    # ====================================================
    # 📍 Implementation Detection (with confidence scoring)
    # ====================================================
    async def _detect_implementations(self) -> Dict[str, Any]:
        checks = [
            self._apollo_check(),
            self._hasura_check(),
            self._aws_appsync_check(),
            self._graphql_js_check(),
            self._relay_check(),
            self._prisma_check(),
            self._java_check(),
            self._sangria_check(),
            self._hotchocolate_check(),
            self._nestjs_check(),
            self._mercurius_check()
        ]
        results = await asyncio.gather(*checks, return_exceptions=True)

        detected = [r for r in results if isinstance(r, dict) and r.get("confidence", 0) > 0]
        if not detected:
            return {"implementation": "Unknown", "confidence": 0}

        # Pick highest confidence match
        best = max(detected, key=lambda d: d["confidence"])
        return best

    # ========= Known implementation tests =========
    async def _apollo_check(self):
        return await self._generic_test("Apollo Server", ["apollo-tracing", "apollo-server"], confidence=85)

    async def _hasura_check(self):
        return await self._generic_test("Hasura", ["x-hasura-role", "hasura"], confidence=90)

    async def _aws_appsync_check(self):
        return await self._generic_test("AWS AppSync", ["appsync-api", "x-amzn-requestid"], confidence=95)

    async def _graphql_js_check(self):
        return await self._generic_test("graphql-js", ["locations", "syntax error", "GraphQLError"], confidence=70)

    async def _relay_check(self):
        return await self._generic_test("Relay", ["Connection", "Edge"], confidence=65)

    async def _prisma_check(self):
        return await self._generic_test("Prisma", ["relation", "unique", "id"], confidence=75)

    async def _java_check(self):
        return await self._generic_test("GraphQL Java", ["ValidationError", "graphql-java"], confidence=80)

    async def _sangria_check(self):
        return await self._generic_test("Sangria (Scala)", ["sangria"], confidence=60)

    async def _hotchocolate_check(self):
        return await self._generic_test("HotChocolate (.NET)", ["hotchocolate", "Banana Cake Pop"], confidence=75)

    async def _nestjs_check(self):
        return await self._generic_test("NestJS GraphQL", ["nestjs", "nestjs/graphql"], confidence=60)

    async def _mercurius_check(self):
        return await self._generic_test("Mercurius (Fastify)", ["mercurius"], confidence=65)

    async def _generic_test(self, name, indicators, confidence):
        try:
            query = {"query": "query { __typename }"}
            async with self.session.post(self.endpoint_url, json=query, timeout=6) as r:
                text = await r.text()
                headers = str(r.headers).lower()
                if any(ind.lower() in text.lower() or ind.lower() in headers for ind in indicators):
                    return {"implementation": name, "confidence": confidence}
        except:
            pass
        return {"implementation": "Unknown", "confidence": 0}

    # ============================================
    # 📡 Header + Metadata Extraction
    # ============================================
    async def _get_headers(self) -> Dict[str, str]:
        try:
            async with self.session.options(self.endpoint_url, timeout=5) as r:
                return dict(r.headers)
        except:
            return {}

    async def _extract_metadata(self) -> Dict[str, Any]:
        metadata = {}
        try:
            q = {"query": "query { __schema { types { name } } }"}
            async with self.session.post(self.endpoint_url, json=q, timeout=6) as r:
                text = await r.text()
                # version leaks in errors or stack traces
                version_match = re.search(r"(v?\d+\.\d+\.\d+)", text)
                if version_match:
                    metadata["version_hint"] = version_match.group(1)
        except:
            pass
        return metadata

    # ============================================
    # 🧪 Feature Detection (defer, stream, batch, etc.)
    # ============================================
    async def _detect_features(self) -> List[str]:
        features = []

        tests = [
            self._test_subscriptions(),
            self._test_batch_ops(),
            self._test_defer_stream(),
            self._test_apq_support()
        ]

        results = await asyncio.gather(*tests, return_exceptions=True)
        names = ["subscriptions", "batch_ops", "defer_stream", "persisted_queries"]

        for n, r in zip(names, results):
            if r and not isinstance(r, Exception):
                features.append(n)
        return features

    async def _test_subscriptions(self):
        try:
            async with self.session.get(self.endpoint_url.replace("http", "ws"), timeout=5) as r:
                return r.status in [101, 400]
        except:
            return False

    async def _test_batch_ops(self):
        try:
            payload = [
                {"query": "query { __typename }"},
                {"query": "query { __typename }"}
            ]
            async with self.session.post(self.endpoint_url, json=payload, timeout=6) as r:
                return r.status == 200 and r.headers.get("Content-Type", "").startswith("application/json")
        except:
            return False

    async def _test_defer_stream(self):
        try:
            q = {"query": "query @defer { __typename }"}
            async with self.session.post(self.endpoint_url, json=q, timeout=6) as r:
                txt = await r.text()
                return "defer" in txt.lower() or "stream" in txt.lower()
        except:
            return False

    async def _test_apq_support(self):
        try:
            payload = {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "deadbeef"}}}
            async with self.session.post(self.endpoint_url, json=payload, timeout=6) as r:
                return "persisted" in (await r.text()).lower()
        except:
            return False

    # ============================================
    # 🛡️ Vulnerability Mapping
    # ============================================
    def _map_vulns(self, implementation, version):
        vulns = []
        implementation = implementation.lower()
        if "apollo" in implementation:
            vulns.append("CVE-2020-3435 – Apollo CSRF")
            vulns.append("CVE-2021-21295 – Apollo introspection bypass")
        if "hasura" in implementation:
            vulns.append("CVE-2020-17310 – JWT bypass")
        if "graphql-js" in implementation:
            vulns.append("CVE-2019-9196 – DoS via deeply nested queries")
        return vulns


# 🧪 CLI usage example
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 graphql_fingerprint.py <endpoint_url>")
        sys.exit(1)

    url = sys.argv[1]
    fp = GraphQLFingerprinter(url, verbose=True)
    result = asyncio.run(fp.fingerprint())
    print(json.dumps(result, indent=2))