#!/usr/bin/env python3
"""
GraphQL Crack Engine - Advanced GraphQL Security Assessment Tool
Combines JWT brute-forcing with GraphQL reconnaissance and enumeration

Authorized Testing Use Only
"""

import sys
import os
import argparse
import asyncio
from pathlib import Path

sys.path.append('core')
sys.path.append('utils')

from core.recon.discovery import GraphQLDiscoverer
from core.recon.introspection import IntrospectionAnalyzer
from core.exploit.jwt_bruteforce import JWTBruteforcer
from core.enum.schema_enum import SchemaEnumerator
from utils.helpers import display_banner, setup_logging, legal_warning
from utils.report_generator import ReportGenerator

class GraphQLCrackEngine:
    def __init__(self):
        self.banner = """
        ╔══════════════════════════════════════════════════════════════╗
        ║                   GRAPHQL CRACK ENGINE                       ║
        ║      Advanced GraphQL Security Assessment Toolkit            ║
        ║               Educational & Authorized Use Only              ║
        ╚══════════════════════════════════════════════════════════════╝
        """
        
    async def run_assessment(self, args):
        """Main assessment workflow"""
        from utils.helpers import display_banner, legal_warning
        display_banner()
        legal_warning()
        
        print(f"Target: {args.url}")
        print(f"Assessment Type: {args.mode}")
        print("─" * 60)
        
        results = {
            'target': args.url,
            'mode': args.mode,
            'findings': [],
            'vulnerabilities': []
        }
        
        try:
            # Phase 1: Discovery & Reconnaissance
            if args.mode in ['full', 'recon']:
                await self.phase_discovery(args.url, results)
            
            # Phase 2: JWT Bruteforce & Authentication Testing
            if args.mode in ['full', 'auth']:
                await self.phase_authentication(args, results)
            
            # Phase 3: Schema Enumeration
            if args.mode in ['full', 'enum']:
                await self.phase_enumeration(args.url, results)
            
            # Generate Report
            if args.output:
                self.generate_report(results, args.output)
                
        except Exception as e:
            print(f"Assessment failed: {e}")
            
    async def phase_discovery(self, url, results):
        """Phase 1: GraphQL Endpoint Discovery"""
        from core.recon.discovery import GraphQLDiscoverer
        from core.recon.introspection import IntrospectionAnalyzer
        
        print("\nPHASE 1: GraphQL Endpoint Discovery")
        print("─" * 40)
        
        discoverer = GraphQLDiscoverer(url)
        endpoints = await discoverer.discover_endpoints()
        
        results['discovered_endpoints'] = endpoints
        print(f"Discovered {len(endpoints)} potential GraphQL endpoints")
        
        # Test introspection with error handling
        for endpoint in endpoints[:3]:  # Test first 3 endpoints
            print(f"Testing introspection on {endpoint}")
            analyzer = IntrospectionAnalyzer(endpoint)
            introspection_data = await analyzer.get_introspection()
            
            if introspection_data:
                results['findings'].append({
                    'type': 'introspection_enabled',
                    'endpoint': endpoint,
                    'severity': 'HIGH',
                    'description': 'GraphQL introspection is enabled'
                })
                print("Introspection enabled - schema data available")
                
                # Analyze schema for sensitive data with error handling
                try:
                    schema_analysis = analyzer.analyze_schema(introspection_data)
                    results['schema_analysis'] = schema_analysis
                    print(f"Schema analysis completed: {len(schema_analysis.get('sensitive_queries', []))} sensitive queries found")
                except Exception as e:
                    print(f"Schema analysis failed: {e}")
                    # Create empty analysis as fallback
                    results['schema_analysis'] = {
                        'sensitive_queries': [],
                        'sensitive_mutations': [],
                        'authentication_flows': [],
                        'data_exposure': [],
                        'risky_directives': []
                    }
            else:
                print("No introspection data received")

    async def phase_authentication(self, args, results):
        """Phase 2: JWT Authentication Testing"""
        from core.exploit.jwt_bruteforce import JWTBruteforcer
        
        print("\nPHASE 2: JWT Authentication Testing")
        print("─" * 40)
        
        bruteforcer = JWTBruteforcer(args.url)
        
        # Test authentication endpoints
        auth_endpoints = await bruteforcer.discover_auth_endpoints()
        print(f"Found {len(auth_endpoints)} authentication endpoints")
        
        # JWT Bruteforce if token provided
        if args.jwt_token:
            print("Starting JWT secret brute-force...")
            jwt_results = await bruteforcer.bruteforce_jwt(
                args.jwt_token, 
                args.wordlist,
                threads=args.threads
            )
            results['jwt_analysis'] = jwt_results
            
            if jwt_results['success']:
                results['vulnerabilities'].append({
                    'type': 'jwt_weak_secret',
                    'severity': 'CRITICAL',
                    'description': f'JWT secret recovered: {jwt_results["secret"]}',
                    'impact': 'Full authentication bypass possible'
                })
        
        # Test authentication bypasses
        print("Testing authentication bypass techniques...")
        bypass_results = await bruteforcer.test_auth_bypass()
        results['auth_bypass_tests'] = bypass_results

    async def phase_enumeration(self, url, results):
        """Phase 3: Schema Enumeration"""
        from core.enum.schema_enum import SchemaEnumerator
        
        print("\nPHASE 3: Schema Enumeration")
        print("─" * 40)
        
        enumerator = SchemaEnumerator(url)
        
        # Enumerate schema even without introspection
        print("Enumerating GraphQL schema...")
        schema = await enumerator.enumerate_schema()
        
        if schema:
            results['enumerated_schema'] = schema
            print(f"Discovered {len(schema.get('queries', []))} queries, "
                  f"{len(schema.get('mutations', []))} mutations")
            
            # Look for sensitive operations
            sensitive_ops = enumerator.find_sensitive_operations(schema)
            if sensitive_ops:
                results['vulnerabilities'].extend(sensitive_ops)

    def generate_report(self, results, output_file):
        """Generate assessment report"""
        from utils.report_generator import ReportGenerator
        
        reporter = ReportGenerator(results)
        report_path = reporter.generate_html_report(output_file)
        print(f"Full report generated: {report_path}")
def main():
    """Entry point for CLI execution"""
    if len(sys.argv) == 1:
        # No arguments, show help
        os.system("python graphql_crack.py --help")
        return
        
    parser = argparse.ArgumentParser(
        description='GraphQL Crack Engine - Advanced GraphQL Security Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full assessment
  python graphql_crack.py -u https://api.target.com/graphql -m full
  
  # JWT brute-force only
  python graphql_crack.py -u https://api.target.com/graphql -m auth --jwt-token "eyJ0..." --wordlist wordlists/jwt_secrets.txt
  
  # Schema enumeration
  python graphql_crack.py -u https://api.target.com/graphql -m enum
  
  # With custom headers
  python graphql_crack.py -u https://api.target.com/graphql -m full --headers '{"User-Agent": "GraphQL-Scanner/1.0"}'
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, help='Target GraphQL endpoint URL')
    parser.add_argument('-m', '--mode', required=True, 
                       choices=['full', 'recon', 'auth', 'enum'],
                       help='Assessment mode')
    
    # Optional arguments
    parser.add_argument('--jwt-token', help='JWT token for brute-force')
    parser.add_argument('--wordlist', help='Path to JWT secrets wordlist')
    parser.add_argument('-t', '--threads', type=int, default=4, 
                       help='Number of threads for brute-force')
    parser.add_argument('-o', '--output', help='Output report file')
    parser.add_argument('--headers', help='Custom headers as JSON string')
    parser.add_argument('--timeout', type=int, default=30, 
                       help='Request timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Input validation
    if args.mode == 'auth' and not args.jwt_token:
        parser.error("--jwt-token is required for auth mode")
    
    # Run assessment
    engine = GraphQLCrackEngine()
    asyncio.run(engine.run_assessment(args))

if __name__ == "__main__":
    main()
