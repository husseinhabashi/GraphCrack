#!/usr/bin/env python3
"""
GraphQL Field Enumeration Module
Discovers fields and operations through various techniques
"""

import aiohttp
import asyncio
import re
import json
from typing import List, Dict, Any, Set

class FieldEnumerator:
    def __init__(self, endpoint_url: str):
        self.endpoint_url = endpoint_url
        self.session = None
        self.discovered_fields = {
            'queries': set(),
            'mutations': set(),
            'subscriptions': set(),
            'types': set(),
            'fields_by_type': {}
        }
        
    async def enumerate_fields(self) -> Dict[str, Any]:
        """Comprehensive field enumeration using multiple techniques"""
        print("Enumerating GraphQL fields and operations...")
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            # Multiple enumeration techniques
            techniques = [
                self._introspection_enumeration(),
                self._field_suggestion_enumeration(),
            ]
            
            results = await asyncio.gather(*techniques, return_exceptions=True)
            
            # Combine results from all techniques
            for result in results:
                if result and not isinstance(result, Exception):
                    self._merge_discoveries(result)
            
            return {
                'queries': list(self.discovered_fields['queries']),
                'mutations': list(self.discovered_fields['mutations']),
                'subscriptions': list(self.discovered_fields['subscriptions']),
                'types': list(self.discovered_fields['types']),
                'fields_by_type': self.discovered_fields['fields_by_type']
            }
    
    async def _introspection_enumeration(self) -> Dict[str, Any]:
        """Enumerate fields using introspection"""
        discoveries = {
            'queries': set(),
            'mutations': set(),
            'subscriptions': set(),
            'types': set(),
            'fields_by_type': {}
        }
        
        try:
            from core.recon.introspection import IntrospectionAnalyzer
            analyzer = IntrospectionAnalyzer(self.endpoint_url)
            introspection_data = await analyzer.get_introspection()
            
            if introspection_data and '__schema' in introspection_data:
                schema = introspection_data['__schema']
                
                # Extract queries
                if schema.get('queryType'):
                    query_fields = schema['queryType'].get('fields', [])
                    for field in query_fields:
                        discoveries['queries'].add(field['name'])
                
                # Extract mutations
                if schema.get('mutationType'):
                    mutation_fields = schema['mutationType'].get('fields', [])
                    for field in mutation_fields:
                        discoveries['mutations'].add(field['name'])
                        
        except Exception as e:
            print(f"Introspection enumeration failed: {e}")
        
        return discoveries
    
    async def _field_suggestion_enumeration(self) -> Dict[str, Any]:
        """Enumerate fields using field suggestion attacks"""
        discoveries = {
            'queries': set(),
            'mutations': set(),
            'subscriptions': set(),
            'types': set(),
            'fields_by_type': {}
        }
        
        # Common field names to try
        common_fields = [
            # Query fields
            'users', 'user', 'posts', 'post', 'products', 'product',
            'customers', 'customer', 'orders', 'order', 'settings',
            'config', 'profile', 'me', 'currentUser', 'admin',
            'markets', 'currencies', 'trades', 'balance'
        ]
        
        for field in common_fields:
            # Test as query
            query_test = {"query": f"query {{ {field} {{ id }} }}"}
            try:
                async with self.session.post(self.endpoint_url, json=query_test, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'data' in data and data['data'] is not None:
                            discoveries['queries'].add(field)
            except:
                pass
        
        return discoveries
    
    def _merge_discoveries(self, new_discoveries: Dict[str, Any]):
        """Merge new discoveries into main discovery set"""
        for key in ['queries', 'mutations', 'subscriptions', 'types']:
            if key in new_discoveries:
                self.discovered_fields[key].update(new_discoveries[key])
        
        if 'fields_by_type' in new_discoveries:
            for type_name, fields in new_discoveries['fields_by_type'].items():
                if type_name not in self.discovered_fields['fields_by_type']:
                    self.discovered_fields['fields_by_type'][type_name] = set()
                self.discovered_fields['fields_by_type'][type_name].update(fields)
