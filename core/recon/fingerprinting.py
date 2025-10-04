#!/usr/bin/env python3
"""
GraphQL Implementation Fingerprinting Module
"""

import aiohttp
import re
import json
from typing import Dict, Any, List

class GraphQLFingerprinter:
    def __init__(self, endpoint_url: str):
        self.endpoint_url = endpoint_url
        self.session = None
        
    async def fingerprint_implementation(self) -> Dict[str, Any]:
        """Fingerprint GraphQL implementation and version"""
        fingerprint = {
            'implementation': 'unknown',
            'version': 'unknown',
            'features': [],
            'vulnerabilities': [],
            'headers': {},
            'metadata': {}
        }
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Test various implementation-specific features
            tests = [
                self._test_apollo(),
                self._test_relay(),
                self._test_graphql_js(),
                self._test_hasura(),
                self._test_prisma(),
                self._test_aws_appsync(),
                self._test_graphql_java(),
                self._test_sangria()  # Scala implementation
            ]
            
            results = await asyncio.gather(*tests, return_exceptions=True)
            
            # Analyze results
            if any(results):
                if results[0]:  # Apollo
                    fingerprint['implementation'] = 'Apollo Server'
                elif results[1]:  # Relay
                    fingerprint['implementation'] = 'Relay'
                elif results[2]:  # graphql-js
                    fingerprint['implementation'] = 'graphql-js'
                elif results[3]:  # Hasura
                    fingerprint['implementation'] = 'Hasura'
                elif results[4]:  # Prisma
                    fingerprint['implementation'] = 'Prisma'
                elif results[5]:  # AWS AppSync
                    fingerprint['implementation'] = 'AWS AppSync'
                elif results[6]:  # GraphQL Java
                    fingerprint['implementation'] = 'GraphQL Java'
                elif results[7]:  # Sangria
                    fingerprint['implementation'] = 'Sangria (Scala)'
            
            # Get server headers for additional info
            fingerprint['headers'] = await self._get_server_headers()
            
            # Check for additional features
            fingerprint['features'] = await self._detect_features()
            
            # Check for known vulnerabilities
            fingerprint['vulnerabilities'] = await self._check_known_vulnerabilities(fingerprint)
        
        return fingerprint
    
    async def _test_apollo(self) -> bool:
        """Test for Apollo Server"""
        try:
            # Apollo-specific endpoints
            apollo_endpoints = [
                '/.well-known/apollo/server-health',
                '/server-health',
                '/voyager',
                '/graphql-voyager'
            ]
            
            for endpoint in apollo_endpoints:
                try:
                    url = self.endpoint_url.replace('/graphql', endpoint)
                    async with self.session.get(url, timeout=5) as response:
                        if response.status == 200:
                            return True
                except:
                    continue
            
            # Check for Apollo tracing
            query = {"query": "query { __typename }"}
            async with self.session.post(self.endpoint_url, json=query, timeout=5) as response:
                headers = dict(response.headers)
                if 'apollo-tracing' in str(headers).lower():
                    return True
                    
                # Check for Apollo Studio
                if 'apollo' in str(headers).lower():
                    return True
            
            # Test Apollo-specific features
            apollo_query = {
                "query": "query { __schema { directives { name args { name type { name } } } } }"
            }
            async with self.session.post(self.endpoint_url, json=apollo_query, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'data' in data:
                        # Look for Apollo-specific directives
                        directives = data.get('data', {}).get('__schema', {}).get('directives', [])
                        for directive in directives:
                            if directive.get('name') in ['connection', 'client']:
                                return True
            
        except Exception as e:
            pass
            
        return False
    
    async def _test_hasura(self) -> bool:
        """Test for Hasura GraphQL Engine"""
        try:
            # Hasura-specific headers
            headers = {
                'X-Hasura-Role': 'admin',
                'X-Hasura-Admin-Secret': 'test'  # Try common default
            }
            
            query = {"query": "query { __schema { queryType { name } } }"}
            async with self.session.post(self.endpoint_url, json=query, headers=headers, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'data' in data:
                        return True
            
            # Check Hasura metadata endpoint
            metadata_url = self.endpoint_url.replace('/v1/graphql', '/v1/metadata')
            try:
                async with self.session.post(metadata_url, json={"type": "export_metadata"}, timeout=5) as response:
                    if response.status == 200:
                        return True
            except:
                pass
                
        except Exception as e:
            pass
            
        return False
    
    async def _test_aws_appsync(self) -> bool:
        """Test for AWS AppSync"""
        try:
            # AppSync often uses specific domain patterns
            if 'appsync-api' in self.endpoint_url or 'graphql.appsync' in self.endpoint_url:
                return True
            
            # Check for AWS-specific headers
            query = {"query": "query { __typename }"}
            async with self.session.post(self.endpoint_url, json=query, timeout=5) as response:
                headers = dict(response.headers)
                if 'x-amzn-requestid' in headers or 'x-amz-apigw-id' in headers:
                    return True
                    
        except Exception as e:
            pass
            
        return False
    
    async def _test_graphql_js(self) -> bool:
        """Test for graphql-js (reference implementation)"""
        try:
            # graphql-js has specific error formats
            invalid_query = {"query": "query { invalidField }"}
            async with self.session.post(self.endpoint_url, json=invalid_query, timeout=5) as response:
                if response.status == 400:
                    data = await response.json()
                    if 'errors' in data:
                        errors = data['errors']
                        if errors and 'locations' in errors[0]:
                            return True
                            
        except Exception as e:
            pass
            
        return False
    
    async def _test_relay(self) -> bool:
        """Test for Relay"""
        try:
            # Relay often uses specific patterns
            relay_query = {
                "query": """
                query {
                  __schema {
                    types {
                      name
                      fields {
                        name
                        args {
                          name
                          type {
                            name
                            kind
                            ofType {
                              name
                              kind
                            }
                          }
                        }
                      }
                    }
                  }
                }
                """
            }
            
            async with self.session.post(self.endpoint_url, json=relay_query, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    # Relay often has specific type patterns
                    if 'data' in data:
                        types = data.get('data', {}).get('__schema', {}).get('types', [])
                        for type_info in types:
                            if 'Connection' in type_info.get('name', '') or 'Edge' in type_info.get('name', ''):
                                return True
                                
        except Exception as e:
            pass
            
        return False
    
    async def _test_prisma(self) -> bool:
        """Test for Prisma"""
        try:
            # Prisma-specific features
            prisma_query = {
                "query": "query { __schema { directives { name } } }"
            }
            
            async with self.session.post(self.endpoint_url, json=prisma_query, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    directives = data.get('data', {}).get('__schema', {}).get('directives', [])
                    for directive in directives:
                        if directive.get('name') in ['relation', 'unique', 'id']:
                            return True
                            
        except Exception as e:
            pass
            
        return False
    
    async def _test_graphql_java(self) -> bool:
        """Test for GraphQL Java"""
        try:
            # GraphQL Java has specific error characteristics
            invalid_query = {"query": "query { __invalid }"}
            async with self.session.post(self.endpoint_url, json=invalid_query, timeout=5) as response:
                if response.status == 400:
                    data = await response.json()
                    errors = data.get('errors', [])
                    for error in errors:
                        if 'ValidationError' in str(error):
                            return True
                            
        except Exception as e:
            pass
            
        return False
    
    async def _test_sangria(self) -> bool:
        """Test for Sangria (Scala)"""
        try:
            # Sangria often includes specific metadata
            query = {"query": "query { __schema { types { name description } } }"}
            async with self.session.post(self.endpoint_url, json=query, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    # Sangria might include specific patterns in descriptions
                    types = data.get('data', {}).get('__schema', {}).get('types', [])
                    for type_info in types:
                        desc = type_info.get('description', '')
                        if 'sangria' in desc.lower():
                            return True
                            
        except Exception as e:
            pass
            
        return False
    
    async def _get_server_headers(self) -> Dict[str, str]:
        """Get server headers for fingerprinting"""
        headers = {}
        try:
            async with self.session.get(self.endpoint_url, timeout=5) as response:
                headers = dict(response.headers)
        except:
            pass
        return headers
    
    async def _detect_features(self) -> List[str]:
        """Detect GraphQL features and extensions"""
        features = []
        
        feature_tests = [
            self._test_subscriptions(),
            self._test_batch_operations(),
            self._test_defer_stream(),
            self._test_tracing(),
            self._test_caching()
        ]
        
        results = await asyncio.gather(*feature_tests, return_exceptions=True)
        
        feature_names = ['subscriptions', 'batch_operations', 'defer_stream', 'tracing', 'caching']
        for name, result in zip(feature_names, results):
            if result and not isinstance(result, Exception):
                features.append(name)
        
        return features
    
    async def _test_subscriptions(self) -> bool:
        """Test if subscriptions are supported"""
        try:
            subscription_test = {
                "query": "subscription { userCreated { id name } }"
            }
            async with self.session.post(self.endpoint_url, json=subscription_test, timeout=5) as response:
                # Even if it errors, the endpoint might support subscriptions
                if response.status in [200, 400]:
                    data = await response.json()
                    return 'subscription' in str(data).lower()
        except:
            pass
        return False
    
    async def _test_batch_operations(self) -> bool:
        """Test if batch operations are supported"""
        try:
            batch_payload = [
                {"query": "query { __typename }"},
                {"query": "query { __schema { types { name } } }"}
            ]
            async with self.session.post(self.endpoint_url, json=batch_payload, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    return isinstance(data, list)
        except:
            pass
        return False
    
    async def _test_tracing(self) -> bool:
        """Test if Apollo Tracing is enabled"""
        try:
            query = {"query": "query { __typename }"}
            async with self.session.post(self.endpoint_url, json=query, timeout=5) as response:
                headers = dict(response.headers)
                if 'tracing' in str(headers).lower() or 'apollo-tracing' in str(headers).lower():
                    return True
                    
                data = await response.json()
                if 'extensions' in data and 'tracing' in data['extensions']:
                    return True
        except:
            pass
        return False
    
    async def _check_known_vulnerabilities(self, fingerprint: Dict[str, Any]) -> List[str]:
        """Check for known implementation-specific vulnerabilities"""
        vulnerabilities = []
        implementation = fingerprint.get('implementation', '').lower()
        
        # Apollo-specific vulnerabilities
        if 'apollo' in implementation:
            vulnerabilities.extend([
                'CVE-2020-3435: Apollo Server CSRF',
                'CVE-2021-21295: Apollo Server introspection bypass'
            ])
        
        # Hasura-specific vulnerabilities
        if 'hasura' in implementation:
            vulnerabilities.extend([
                'CVE-2020-17310: Hasura JWT vulnerability',
                'CVE-2021-21297: Hasura role escalation'
            ])
        
        # graphql-js vulnerabilities
        if 'graphql-js' in implementation:
            vulnerabilities.extend([
                'CVE-2019-9196: GraphQL-js DoS',
                'CVE-2020-15009: GraphQL-js field duplication'
            ])
        
        return vulnerabilities