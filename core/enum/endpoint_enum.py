#!/usr/bin/env python3
"""
GraphQL Endpoint Enumeration Module
Discovers additional GraphQL endpoints and API routes
"""

import aiohttp
import asyncio
from urllib.parse import urljoin, urlparse
import re
from typing import List, Dict, Any

class EndpointEnumerator:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = None
        self.discovered_endpoints = []
        
    async def enumerate_endpoints(self) -> List[Dict[str, Any]]:
        """Comprehensive endpoint enumeration"""
        print("🔍 Enumerating GraphQL endpoints...")
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Multiple enumeration techniques
            techniques = [
                self._common_path_enumeration(),
            ]
            
            results = await asyncio.gather(*techniques, return_exceptions=True)
            
            # Combine and deduplicate results
            all_endpoints = []
            for result in results:
                if result and not isinstance(result, Exception):
                    all_endpoints.extend(result)
            
            # Test discovered endpoints
            tested_endpoints = await self._test_endpoints(all_endpoints)
            
            return tested_endpoints
    
    async def _common_path_enumeration(self) -> List[str]:
        """Enumerate common GraphQL paths"""
        common_paths = [
            # Standard paths
            '/graphql', '/api/graphql', '/gql', '/query',
            '/api', '/v1/graphql', '/v2/graphql', '/v3/graphql',
            '/graphql-api', '/graphql/console',
            
            # Admin paths
            '/admin/graphql', '/internal/graphql',
            
            # Framework-specific paths
            '/hasura/v1/graphql',
            
            # Alternative API paths
            '/graphql/v1', '/graphql/v2', '/api/v1/graphql', 
            '/api/v2/graphql',
        ]
        
        endpoints = []
        for path in common_paths:
            endpoints.append(urljoin(self.base_url, path))
        
        return endpoints
    
    async def _test_endpoints(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Test if endpoints are valid GraphQL endpoints"""
        valid_endpoints = []
        
        # Test each endpoint
        test_tasks = []
        for endpoint in set(endpoints):  # Remove duplicates
            test_tasks.append(self._test_single_endpoint(endpoint))
        
        results = await asyncio.gather(*test_tasks, return_exceptions=True)
        
        for endpoint, result in zip(set(endpoints), results):
            if result and not isinstance(result, Exception):
                valid_endpoints.append({
                    'url': endpoint,
                    'graphql': result['is_graphql'],
                    'introspection': result['introspection_enabled'],
                    'implementation': result.get('implementation', 'unknown')
                })
        
        return valid_endpoints
    
    async def _test_single_endpoint(self, endpoint: str) -> Dict[str, Any]:
        """Test a single endpoint for GraphQL functionality"""
        result = {
            'is_graphql': False,
            'introspection_enabled': False,
            'implementation': 'unknown'
        }
        
        try:
            # Test basic GraphQL query
            test_query = {"query": "query { __typename }"}
            async with self.session.post(endpoint, json=test_query, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('data', {}).get('__typename') == 'Query':
                        result['is_graphql'] = True
            
            # Test introspection if GraphQL endpoint
            if result['is_graphql']:
                introspection_query = {"query": "query { __schema { types { name } } }"}
                async with self.session.post(endpoint, json=introspection_query, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('data', {}).get('__schema'):
                            result['introspection_enabled'] = True
                            
        except Exception as e:
            # Endpoint might not exist or be unreachable
            pass
        
        return result
