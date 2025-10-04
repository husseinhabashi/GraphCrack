#!/usr/bin/env python3
"""
GraphQL Introspection Analysis Module
"""

import aiohttp
import json
import re

class IntrospectionAnalyzer:
    def __init__(self, endpoint_url):
        self.endpoint_url = endpoint_url
        self.session = None
        
    async def get_introspection(self):
        """Get full introspection schema"""
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
        
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"query": introspection_query}
                
                async with session.post(self.endpoint_url, json=payload, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'data' in data:
                            return data['data']
        except Exception as e:
            print(f"Introspection failed: {e}")
            
        return None

    def analyze_schema(self, introspection_data):
        """Analyze introspection data for security issues"""
        analysis = {
            'sensitive_queries': [],
            'sensitive_mutations': [],
            'authentication_flows': [],
            'data_exposure': [],
            'risky_directives': []
        }
        
        try:
            # Handle None or empty data
            if not introspection_data or '__schema' not in introspection_data:
                return analysis
                
            schema = introspection_data['__schema']
            types = schema.get('types', [])
            
            if not isinstance(types, list):
                return analysis
            
            for type_info in types:
                if not isinstance(type_info, dict):
                    continue
                    
                type_name = type_info.get('name', '')
                fields = type_info.get('fields', [])
                
                if not isinstance(fields, list):
                    continue
                
                # Analyze queries and mutations
                for field in fields:
                    if not isinstance(field, dict):
                        continue
                        
                    field_name = field.get('name', '')
                    field_desc = field.get('description', '')
                    if field_desc:
                        field_desc = field_desc.lower()
                    else:
                        field_desc = ''  # Empty string instead of None
                    
                    # Look for sensitive operations
                    if self.is_sensitive_field(field_name, field_desc):
                        analysis['sensitive_queries'].append({
                            'type': type_name,
                            'field': field_name,
                            'description': field_desc
                        })
                    
                    # Look for authentication-related fields
                    if self.is_auth_field(field_name, field_desc):
                        analysis['authentication_flows'].append({
                            'type': type_name,
                            'field': field_name,
                            'description': field_desc
                        })
        except Exception as e:
            # If any error occurs, return the empty analysis
            print(f"Schema analysis error: {e}")
        
        return analysis

    def is_sensitive_field(self, field_name, description):
        """Check if field is sensitive"""
        sensitive_keywords = [
            'user', 'users', 'customer', 'admin', 'password',
            'token', 'secret', 'key', 'credential', 'auth',
            'permission', 'role', 'privilege', 'account',
            'email', 'phone', 'address', 'ssn', 'credit'
        ]
        
        # Handle None values
        if not field_name:
            return False
            
        field_lower = field_name.lower()
        desc_lower = description.lower() if description else ''
        
        for keyword in sensitive_keywords:
            if keyword in field_lower or keyword in desc_lower:
                return True
        return False

    def is_auth_field(self, field_name, description):
        """Check if field is authentication-related"""
        auth_keywords = [
            'login', 'auth', 'authenticate', 'token', 'jwt',
            'session', 'signin', 'signup', 'register', 'oauth'
        ]
        
        # Handle None values
        if not field_name:
            return False
            
        field_lower = field_name.lower()
        desc_lower = description.lower() if description else ''
        
        for keyword in auth_keywords:
            if keyword in field_lower or keyword in desc_lower:
                return True
        return False
