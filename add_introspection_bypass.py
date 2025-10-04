#!/usr/bin/env python3
"""
Add the missing test_introspection_bypass method
"""

def add_introspection_bypass():
    # Read the current file
    with open('core/exploit/jwt_bruteforce.py', 'r') as f:
        content = f.read()
    
    # Check if the method already exists
    if 'async def test_introspection_bypass' in content:
        print("test_introspection_bypass method already exists")
        return
    
    # Add the method before the test_auth_bypass method
    new_method = '''
    async def test_introspection_bypass(self):
        """Test introspection bypass techniques"""
        bypass_attempts = [
            # Try with different content types
            {"headers": {"Content-Type": "application/json"}},
            {"headers": {"Content-Type": "application/graphql"}},
            # Try with different HTTP methods
            {"method": "GET"},
            {"method": "POST"},
            # Try with different parameter names
            {"params": {"query": "{ __schema { types { name } } }"}},
            {"params": {"q": "{ __schema { types { name } } }"}}
        ]
        
        results = {}
        
        async with aiohttp.ClientSession() as session:
            for i, attempt in enumerate(bypass_attempts):
                try:
                    url = self.endpoint
                    test_name = f"attempt_{i}"
                    
                    if attempt.get('method') == 'GET':
                        async with session.get(url, **{k: v for k, v in attempt.items() if k != 'method'}, timeout=5) as response:
                            if response.status == 200:
                                data = await response.json()
                                if 'data' in data:
                                    results[test_name] = {'success': True, 'technique': str(attempt)}
                                    continue
                    else:
                        async with session.post(url, **{k: v for k, v in attempt.items() if k != 'method'}, timeout=5) as response:
                            if response.status == 200:
                                data = await response.json()
                                if 'data' in data:
                                    results[test_name] = {'success': True, 'technique': str(attempt)}
                                    continue
                    
                    results[test_name] = {'success': False, 'technique': str(attempt)}
                    
                except Exception as e:
                    results[test_name] = {'success': False, 'error': str(e), 'technique': str(attempt)}
        
        return results'''
    
    # Find where to insert the method (before test_auth_bypass)
    lines = content.split('\\n')
    insert_index = None
    
    for i, line in enumerate(lines):
        if 'async def test_auth_bypass' in line:
            insert_index = i
            break
    
    if insert_index is not None:
        lines.insert(insert_index, new_method)
        with open('core/exploit/jwt_bruteforce.py', 'w') as f:
            f.write('\\n'.join(lines))
        print("Added test_introspection_bypass method")
    else:
        print("Could not find where to insert the method")

if __name__ == "__main__":
    add_introspection_bypass()
