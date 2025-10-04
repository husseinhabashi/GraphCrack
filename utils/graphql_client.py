#!/usr/bin/env python3
"""
GraphQL Client Utilities for making requests
"""

import aiohttp
import json
import asyncio
from typing import Dict, Any, Optional

class GraphQLClient:
    def __init__(self, endpoint: str, headers: Optional[Dict] = None):
        self.endpoint = endpoint
        self.headers = headers or {
            'Content-Type': 'application/json',
            'User-Agent': 'GraphQL-Crack-Engine/1.0'
        }
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def execute_query(self, query: str, variables: Optional[Dict] = None, 
                          operation_name: Optional[str] = None) -> Dict[str, Any]:
        """Execute GraphQL query"""
        payload = {'query': query}
        
        if variables:
            payload['variables'] = variables
        if operation_name:
            payload['operationName'] = operation_name
            
        try:
            async with self.session.post(self.endpoint, json=payload) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    return {
                        'errors': [{
                            'message': f'HTTP {response.status}: {await response.text()}'
                        }]
                    }
        except Exception as e:
            return {
                'errors': [{
                    'message': f'Request failed: {str(e)}'
                }]
            }
    
    async def execute_introspection(self) -> Dict[str, Any]:
        """Execute full introspection query"""
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        return await self.execute_query(introspection_query)
    
    async def test_endpoint(self) -> bool:
        """Test if endpoint is a valid GraphQL endpoint"""
        test_query = {"query": "query { __typename }"}
        
        try:
            async with self.session.post(self.endpoint, json=test_query) as response:
                if response.status == 200:
                    data = await response.json()
                    return 'data' in data and data.get('data', {}).get('__typename') == 'Query'
        except:
            pass
            
        return False