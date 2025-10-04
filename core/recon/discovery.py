#!/usr/bin/env python3
"""
GraphQL Endpoint Discovery Module
"""

import aiohttp
import asyncio
from urllib.parse import urljoin
import json
import re

class GraphQLDiscoverer:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = None
        self.common_paths = [
            '/graphql', '/api/graphql', '/gql', '/query',
            '/api', '/v1/graphql', '/v2/graphql',
            '/graphql-api', '/graphql/console',
            '/admin/graphql', '/internal/graphql'
        ]
        
    async def discover_endpoints(self):
        """Discover GraphQL endpoints"""
        endpoints = []
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Test common paths
            tasks = []
            for path in self.common_paths:
                url = urljoin(self.base_url, path)
                tasks.append(self.test_graphql_endpoint(url))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for url, is_graphql in zip([urljoin(self.base_url, p) for p in self.common_paths], results):
                if is_graphql and not isinstance(is_graphql, Exception):
                    endpoints.append(url)
        
        return endpoints
    
    async def test_graphql_endpoint(self, url):
        """Test if URL is a GraphQL endpoint"""
        try:
            # Test with introspection query
            introspection_query = {
                "query": "query { __schema { types { name } } }"
            }
            
            async with self.session.post(url, json=introspection_query, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    # Check for GraphQL response patterns
                    if self.is_graphql_response(data):
                        return True
                
            # Test with invalid query to check for GraphQL error format
            invalid_query = {
                "query": "query { invalidField }"
            }
            
            async with self.session.post(url, json=invalid_query, timeout=10) as response:
                if response.status == 400:
                    data = await response.json()
                    if self.is_graphql_error(data):
                        return True
                        
        except Exception:
            return False
            
        return False
    
    def is_graphql_response(self, data):
        """Check if response is GraphQL format"""
        if isinstance(data, dict):
            # Check for GraphQL success response
            if 'data' in data and isinstance(data['data'], dict):
                return True
            # Check for GraphQL error response
            if 'errors' in data and isinstance(data['errors'], list):
                return True
        return False
    
    def is_graphql_error(self, data):
        """Check if error is GraphQL format"""
        if isinstance(data, dict) and 'errors' in data:
            errors = data['errors']
            if isinstance(errors, list) and len(errors) > 0:
                error = errors[0]
                if isinstance(error, dict) and 'message' in error:
                    return True
        return False