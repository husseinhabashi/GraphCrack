#!/usr/bin/env python3
"""
Payload Generator for GraphQL testing
"""

import json
from typing import List, Dict, Any

class PayloadGenerator:
    def __init__(self):
        self.common_queries = self._load_common_queries()
        self.common_mutations = self._load_common_mutations()
    
    def _load_common_queries(self) -> List[Dict[str, str]]:
        """Load common GraphQL query templates"""
        return [
            {
                "name": "introspection",
                "query": "query { __schema { types { name } } }"
            },
            {
                "name": "get_users",
                "query": "query { users { id name email } }"
            },
            {
                "name": "get_current_user",
                "query": "query { me { id username email role } }"
            },
            {
                "name": "get_posts",
                "query": "query { posts { id title content author { id name } } }"
            },
            {
                "name": "get_settings",
                "query": "query { settings { key value } }"
            }
        ]
    
    def _load_common_mutations(self) -> List[Dict[str, str]]:
        """Load common GraphQL mutation templates"""
        return [
            {
                "name": "login",
                "query": 'mutation { login(input: {email: "test@test.com", password: "password"}) { token user { id } } }'
            },
            {
                "name": "create_user",
                "query": 'mutation { createUser(input: {email: "test@test.com", password: "password"}) { id } }'
            },
            {
                "name": "update_user",
                "query": 'mutation { updateUser(id: 1, input: {email: "test@test.com"}) { id } }'
            },
            {
                "name": "delete_user",
                "query": 'mutation { deleteUser(id: 1) { success } }'
            }
        ]
    
    def generate_field_suggestion_payloads(self, field_name: str) -> List[Dict[str, str]]:
        """Generate payloads for field suggestion attacks"""
        payloads = []
        
        # Basic field query
        payloads.append({
            "name": f"basic_{field_name}",
            "query": f"query {{ {field_name} {{ id }} }}"
        })
        
        # With common sub-fields
        common_fields = ["id", "name", "email", "title", "content", "createdAt", "updatedAt"]
        for sub_field in common_fields:
            payloads.append({
                "name": f"{field_name}_{sub_field}",
                "query": f"query {{ {field_name} {{ {sub_field} }} }}"
            })
        
        return payloads
    
    def generate_introspection_bypass_payloads(self) -> List[Dict[str, str]]:
        """Generate payloads for introspection bypass attempts"""
        bypass_techniques = [
            {
                "name": "alias_introspection",
                "query": "query { a: __schema { types { name } } }"
            },
            {
                "name": "fragment_introspection", 
                "query": "query { ...Intro } fragment Intro on Query { __schema { types { name } } }"
            },
            {
                "name": "inline_fragment",
                "query": "query { ... on Query { __schema { types { name } } } }"
            }
        ]
        
        return bypass_techniques
    
    def generate_batch_query_payload(self, queries: List[str]) -> Dict[str, Any]:
        """Generate batch query payload"""
        batch_payload = []
        
        for i, query in enumerate(queries):
            batch_payload.append({
                "query": query,
                "variables": {},
                "operationName": f"op_{i}"
            })
        
        return batch_payload