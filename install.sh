#!/bin/bash

echo "Installing GraphQL Crack Engine..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3.7+ is required"
    exit 1
fi

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p reports payloads wordlists

# Make scripts executable
chmod +x graphql_crack.py

# Create default wordlists
echo "Creating default wordlists..."
cat > wordlists/jwt_secrets.txt << 'EOF'
secret
education
graphql
password
admin
123456
test
key
jwt
token
security
authentication
bearer
api
default
development
production
changeme
letmein
access
master
root
super
admin123
qwerty
password123
secret123
test123
demo123
EOF

cat > wordlists/graphql_paths.txt << 'EOF'
/graphql
/api/graphql
/gql
/query
/api
/v1/graphql
/v2/graphql
/graphql-api
/graphql/console
/admin/graphql
/internal/graphql
/api/v1/graphql
/api/v2/graphql
/graphql/v1
/graphql/v2
EOF

echo ""
echo "Installation complete"
echo ""
echo "Usage examples:"
echo "  python graphql_crack.py -u https://api.target.com/graphql -m full"
echo "  python graphql_crack.py -u https://api.target.com/graphql -m auth --jwt-token \"eyJ...\" --wordlist wordlists/jwt_secrets.txt"
echo "  python graphql_crack.py -u https://api.target.com/graphql -m recon"
echo ""
echo "See the documentation for advanced usage"