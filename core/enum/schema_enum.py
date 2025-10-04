#!/usr/bin/env python3
"""
GraphQL Schema Enumeration Module
"""

import aiohttp
import json
import re

class SchemaEnumerator:
    def __init__(self, endpoint_url):
        self.endpoint_url = endpoint_url
        self.session = None
        
    async def enumerate_schema(self):
        """Enumerate GraphQL schema through field suggestions"""
        schema = {
            'queries': [],
            'mutations': [],
            'subscriptions': []
        }
        
        # Common field patterns for discovery
        discovery_queries = [
            # Try to get root types
            {"query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }"},
            
            # Try common query names
            {"query": "{ users { id } }"},
            {"query": "{ posts { id } }"},
            {"query": "{ products { id } }"},
            {"query": "{ markets { id } }"},
        ]
        
        async with aiohttp.ClientSession() as session:
            for attempt in discovery_queries:
                try:
                    async with session.post(self.endpoint_url, json=attempt, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Analyze response for schema information
                            self.analyze_response_for_schema(data, schema)
                            
                except Exception as e:
                    continue
        
        return schema
    
    def analyze_response_for_schema(self, response_data, schema):
        """Analyze GraphQL responses for schema information"""
        if 'errors' in response_data:
            errors = response_data['errors']
            for error in errors:
                if 'message' in error:
                    message = error['message']
                    # Extract field names from error messages
                    self.extract_fields_from_error(message, schema)
        
        if 'data' in response_data and response_data['data']:
            # Successful queries reveal schema structure
            data = response_data['data']
            self.extract_fields_from_data(data, schema)
    
    def extract_fields_from_error(self, error_message, schema):
        """Extract field names from GraphQL error messages"""
        # Common error patterns that reveal schema
        patterns = [
            r'Cannot query field \"(\w+)\"',
            r'Field \"(\w+)\" is not defined',
            r'Cannot query field \"(\w+)\" on type',
            r'Unknown field \"(\w+)\"'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, error_message)
            for match in matches:
                if match not in schema['queries'] and not match.startswith('__'):
                    schema['queries'].append(match)
    
    def extract_fields_from_data(self, data, schema):
        """Extract field names from successful query responses"""
        if isinstance(data, dict):
            for key, value in data.items():
                if key not in schema['queries'] and not key.startswith('__'):
                    schema['queries'].append(key)
                
                if isinstance(value, dict):
                    self.extract_fields_from_data(value, schema)
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    for item in value:
                        self.extract_fields_from_data(item, schema)
    
    def find_sensitive_operations(self, schema):
        """Find sensitive operations in enumerated schema"""
        sensitive_operations = []
        
        sensitive_keywords = [
            'user', 'admin', 'password', 'token', 'secret',
            'key', 'credential', 'auth', 'permission', 'role',
            'delete', 'drop', 'remove', 'update', 'create'
        ]
        
        for query in schema.get('queries', []):
            query_lower = query.lower()
            for keyword in sensitive_keywords:
                if keyword in query_lower:
                    sensitive_operations.append({
                        'type': 'query',
                        'operation': query,
                        'risk': 'information_disclosure',
                        'severity': 'MEDIUM'
                    })
                    break
        
        return sensitive_operations
