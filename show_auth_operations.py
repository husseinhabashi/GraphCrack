#!/usr/bin/env python3
"""
Show the exact authentication operations that were tested
"""

import asyncio
import aiohttp
from core.exploit.jwt_bruteforce import JWTBruteforcer

async def show_auth_operations():
    target_url = "https://exchange-api.bumba.global/graphql"
    
    print("EXACT AUTHENTICATION OPERATIONS TESTED")
    print("=" * 60)
    
    # Show what operations the tool tests by default
    print("\\nDEFAULT AUTHENTICATION OPERATIONS PATTERNS:")
    print("-" * 50)
    
    auth_queries = [
        "query { __typename }",
        "query { viewer { id } }",
        "query { me { id } }", 
        "query { currentUser { id } }",
        "query { user { id } }"
    ]
    
    auth_mutations = [
        'mutation { login(input: {username: "test", password: "test"}) { token } }',
        'mutation { auth(input: {username: "test", password: "test"}) { token } }',
        'mutation { authenticate(input: {credentials: "test"}) { jwt } }'
    ]
    
    print("\\nQUERIES TESTED:")
    for i, query in enumerate(auth_queries, 1):
        print(f"{i}. {query}")
    
    print("\\nMUTATIONS TESTED:")
    for i, mutation in enumerate(auth_mutations, 1):
        print(f"{i}. {mutation}")
    
    print("\\nTESTING THESE OPERATIONS ON THE TARGET...")
    print("-" * 50)
    
    bruteforcer = JWTBruteforcer(target_url)
    auth_results = await bruteforcer.discover_auth_endpoints()
    
    print(f"\\RESULTS: {len(auth_results)} operations responded")
    print("-" * 50)
    
    successful_ops = [op for op in auth_results if op.get('has_data') or op.get('status') == 200]
    error_ops = [op for op in auth_results if op.get('has_errors')]
    no_response_ops = [op for op in auth_results if not op.get('has_data') and not op.get('has_errors')]
    
    print(f"Operations with data: {len(successful_ops)}")
    print(f"Operations with errors: {len(error_ops)}")
    print(f"Operations with no response: {len(no_response_ops)}")
    
    if successful_ops:
        print("\\nOPERATIONS THAT RETURNED DATA (Potential endpoints):")
        for op in successful_ops:
            print(f"   - {op.get('operation', 'Unknown')}")
            if 'response_sample' in op:
                sample = op['response_sample']
                if isinstance(sample, dict) and 'data' in sample:
                    data_keys = list(sample['data'].keys()) if sample['data'] else []
                    print(f"     Data returned: {data_keys}")

if __name__ == "__main__":
    asyncio.run(show_auth_operations())
