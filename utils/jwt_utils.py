#!/usr/bin/env python3
"""
JWT Utilities for token analysis and manipulation
"""

import jwt
import base64
import json
from typing import Dict, Any, Optional

class JWTUtils:
    @staticmethod
    def decode_token(token: str, verify: bool = False) -> Optional[Dict[str, Any]]:
        """Decode JWT token without verification"""
        try:
            # Try to decode without verification first
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except Exception as e:
            print(f"Failed to decode token: {e}")
            return None
    
    @staticmethod
    def analyze_token(token: str) -> Dict[str, Any]:
        """Analyze JWT token structure and content"""
        analysis = {
            'valid': False,
            'header': {},
            'payload': {},
            'algorithm': None,
            'vulnerabilities': []
        }
        
        try:
            # Split token
            parts = token.split('.')
            if len(parts) != 3:
                analysis['vulnerabilities'].append('Invalid JWT format')
                return analysis
            
            # Decode header and payload
            header = json.loads(base64.b64decode(parts[0] + '==').decode('utf-8'))
            payload = json.loads(base64.b64decode(parts[1] + '==').decode('utf-8'))
            
            analysis.update({
                'valid': True,
                'header': header,
                'payload': payload,
                'algorithm': header.get('alg')
            })
            
            # Check for vulnerabilities
            if header.get('alg') == 'none':
                analysis['vulnerabilities'].append('Algorithm "none" vulnerability')
            
            if not header.get('alg'):
                analysis['vulnerabilities'].append('Missing algorithm in header')
            
            # Check for weak algorithms
            weak_algorithms = ['HS256', 'HS384', 'HS512']  # These are brute-forceable
            if header.get('alg') in weak_algorithms:
                analysis['vulnerabilities'].append(f'Using brute-forceable algorithm: {header.get("alg")}')
            
            # Check expiration
            if 'exp' in payload:
                from time import time
                if payload['exp'] < time():
                    analysis['vulnerabilities'].append('Token has expired')
            
        except Exception as e:
            analysis['vulnerabilities'].append(f'Token analysis failed: {e}')
        
        return analysis
    
    @staticmethod
    def is_token_expired(payload: Dict[str, Any]) -> bool:
        """Check if token is expired"""
        from time import time
        exp = payload.get('exp')
        return exp is not None and exp < time()
    
    @staticmethod
    def create_test_token(secret: str, algorithm: str = 'HS256', payload: Optional[Dict] = None) -> str:
        """Create a test JWT token for validation"""
        default_payload = {
            'sub': '1234567890',
            'name': 'Test User',
            'iat': 1516239022,
            'exp': 9999999999
        }
        
        if payload:
            default_payload.update(payload)
        
        return jwt.encode(default_payload, secret, algorithm=algorithm)