#!/usr/bin/env python3
"""
Debug script to show exactly what endpoints and authentication endpoints were found
"""

import asyncio
import json
from core.recon.discovery import GraphQLDiscoverer
from core.exploit.jwt_bruteforce import JWTBruteforcer

async def show_detailed_results():
    target_url = "https://exchange-api.bumba.global/graphql"
    
    print("DETAILED ENDPOINT DISCOVERY RESULTS")
    print("=" * 60)
    
    # Test endpoint discovery
    print("\\nDISCOVERING GRAPHQL ENDPOINTS...")
    discoverer = GraphQLDiscoverer(target_url)
    endpoints = await discoverer.discover_endpoints()
    
    print(f"Found {len(endpoints)} potential GraphQL endpoints:")
    print("-" * 50)
    
    for i, endpoint in enumerate(endpoints, 1):
        print(f"{i}. {endpoint}")
        
        # Test each endpoint to confirm it's GraphQL
        is_graphql = await discoverer.test_graphql_endpoint(endpoint)
        print(f"   GraphQL Confirmed: {is_graphql}")
        
        # Test introspection
        from core.recon.introspection import IntrospectionAnalyzer
        analyzer = IntrospectionAnalyzer(endpoint)
        introspection_data = await analyzer.get_introspection()
        print(f"   Introspection Enabled: {bool(introspection_data)}")
        
        if introspection_data:
            print("   Introspection data available!")
    
    print("\\nDISCOVERING AUTHENTICATION ENDPOINTS...")
    bruteforcer = JWTBruteforcer(target_url)
    auth_endpoints = await bruteforcer.discover_auth_endpoints()
    
    print(f"Found {len(auth_endpoints)} authentication-related operations:")
    print("-" * 50)
    
    for i, auth_op in enumerate(auth_endpoints, 1):
        print(f"\\n{i}. Type: {auth_op.get('type', 'Unknown')}")
        print(f"   Operation: {auth_op.get('operation', 'Unknown')}")
        print(f"   Status: {auth_op.get('status', 'Unknown')}")
        print(f"   Has Data: {auth_op.get('has_data', False)}")
        print(f"   Has Errors: {auth_op.get('has_errors', False)}")
        
        # Show more details if available
        if 'response_sample' in auth_op:
            sample = auth_op['response_sample']
            if isinstance(sample, dict):
                print(f"   Response Keys: {list(sample.keys())}")
    
    print("\\nTESTING ACTUAL AUTHENTICATION OPERATIONS...")
    print("-" * 50)
    
    # Test the actual authentication operations
    async with aiohttp.ClientSession() as session:
        for auth_op in auth_endpoints:
            operation = auth_op.get('operation', '')
            if operation and 'query' in operation:
                print(f"\\n🔧 Testing: {operation[:80]}...")
                try:
                    payload = {"query": operation}
                    async with session.post(target_url, json=payload, timeout=10) as response:
                        data = await response.json() if response.status == 200 else {}
                        print(f"   Status: {response.status}")
                        
                        if 'data' in data and data['data']:
                            print("   Returns data (might be unauthenticated)")
                        elif 'errors' in data:
                            first_error = data['errors'][0] if data['errors'] else {}
                            error_msg = first_error.get('message', 'Unknown error')
                            print(f"   Error: {error_msg}")
                        else:
                            print("    No data returned")
                except Exception as e:
                    print(f"   Failed: {e}")

if __name__ == "__main__":
    import aiohttp
    asyncio.run(show_detailed_results())
