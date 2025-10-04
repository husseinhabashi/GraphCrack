# #!/usr/bin/env python3
# """
# Create test JWT tokens for brute-force demonstration
# """

# import jwt
# import json

# # Create a JWT with a secret we know
# test_secret = "education"
# test_payload = {
#     "user": "admin",
#     "role": "administrator", 
#     "iat": 1516239022,
#     "exp": 9999999999
# }

# # Generate the token
# token = jwt.encode(test_payload, test_secret, algorithm="HS256")
# print("🔐 Test JWT Token (signed with 'education'):")
# print(token)
# print()

# # Also create tokens with other common secrets for testing
# secrets = ["secret", "password", "admin", "123456", "test"]
# for secret in secrets:
#     test_token = jwt.encode(test_payload, secret, algorithm="HS256")
#     print(f"Token with secret '{secret}': {test_token}")

# print("\n💡 Save the first token to test brute-force:")
# print(f"python graphql_crack.py -u https://countries.trevorblades.com -m auth --jwt-token '{token}' --wordlist wordlists/jwt_secrets.txt")
