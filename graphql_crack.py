#!/usr/bin/env python3
"""
graphql_crack.py — GraphQL Crack Engine (production-ready CLI runner)

Features:
- Clear async phase orchestration (discovery / auth / enumeration)
- Centralized error handling (safe_run) with trace capture
- Verbose / logging support (uses utils.helpers.setup_logging if available)
- Header / timeout propagation to submodules via setattr
- Saves raw JSON artifacts on completion or error
- Risk scoring per finding + overall score
- Graceful KeyboardInterrupt handling
- Entry point: cli() — suitable for packaging console_scripts

Authorized testing only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import traceback
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# ---- Risk scoring ----
try:
    from utils.risk import compute_risk_score, aggregate_target_score, map_severity_label
except Exception:
    # Minimal fallback if utils.risk isn't available
    def compute_risk_score(f: Dict[str, Any]) -> Dict[str, Any]:
        f.setdefault("risk_score", {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 55, "LOW": 25}.get(f.get("severity", "MEDIUM"), 55))
        f.setdefault("risk_label", f.get("severity", "MEDIUM"))
        return f
    def aggregate_target_score(vulns): return int(sum(v.get("risk_score", 0) for v in vulns) / max(1, len(vulns)))
    def map_severity_label(score: int) -> str:
        return "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score >= 15 else "INFO"

# ---- Try importing helper utilities if present (fall back safely) ----
try:
    from utils.helpers import (
        display_banner,
        legal_warning,
        setup_logging,
        save_json as helpers_save_json,
        print_info,
        print_success,
        print_error,
        print_warning,
    )
except Exception:
    def display_banner(): print("GRAPHQL CRACK ENGINE")
    def legal_warning(): print("LEGAL WARNING: Authorized use only.\n" + ("─" * 60))
    def setup_logging(verbose: bool = False):
        import logging
        lvl = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=lvl, format="%(asctime)s - %(levelname)s - %(message)s")
        return logging.getLogger("GraphQLCrack")
    def helpers_save_json(data, filename: str) -> bool:
        try:
            with open(filename, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
    def print_info(msg: str): print(f"[*] {msg}")
    def print_success(msg: str): print(f"[+] {msg}")
    def print_error(msg: str): print(f"[!] {msg}")
    def print_warning(msg: str): print(f"[⚠] {msg}")

# ---- Safe dynamic imports for core modules (fail gracefully) ----
def try_import(module_path: str, class_name: str):
    try:
        module = __import__(module_path, fromlist=[class_name])
        return getattr(module, class_name)
    except Exception as e:
        print_warning(f"Optional module import failed: {module_path}.{class_name} — {e}")
        return None

GraphQLDiscoverer   = try_import("core.recon.discovery", "GraphQLDiscoverer")
IntrospectionAnalyzer = try_import("core.recon.introspection", "IntrospectionAnalyzer")
JWTBruteforcer      = try_import("core.exploit.jwt_bruteforce", "JWTBruteforcer")
SchemaEnumerator    = try_import("core.enum.schema_enum", "SchemaEnumerator")
ReportGenerator     = try_import("utils.report_generator", "ReportGenerator")

# ---- Data classes for structured results ----
@dataclass
class EngineOptions:
    url: str
    mode: str
    jwt_token: Optional[str] = None
    wordlist: Optional[str] = None
    threads: int = 4
    output: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    timeout: int = 30
    verbose: bool = False

# ---- Engine ----
class GraphQLCrackEngine:
    def __init__(self, opts: EngineOptions, logger=None):
        self.opts = opts
        self.logger = logger or setup_logging(opts.verbose)
        self.results: Dict[str, Any] = {
            "meta": {
                "target": opts.url,
                "mode": opts.mode,
                "started_at": datetime.utcnow().isoformat() + "Z",
                "options": {k: v for k, v in asdict(opts).items() if k != "headers"},
            },
            "discovered_endpoints": [],
            "schema_analysis": {},
            "jwt_analysis": {},
            "auth_bypass_tests": {},
            "enumerated_schema": {},
            "vulnerabilities": [],
            "findings": [],
            "errors": [],
        }
        if opts.headers:
            self.results["meta"]["options"]["headers"] = opts.headers

    # safe run wrapper
    async def safe_run(self, coro, phase_name: str) -> Any:
        try:
            return await coro
        except asyncio.CancelledError:
            msg = f"Phase {phase_name} cancelled."
            print_warning(msg)
            self.results["errors"].append({"phase": phase_name, "error": msg})
            raise
        except Exception as e:
            tb = traceback.format_exc()
            print_error(f"[!] Error during {phase_name}: {e}")
            self.results["errors"].append({"phase": phase_name, "error": str(e), "trace": tb})
            return None

    # Helper to propagate common options to modules
    def _propagate(self, obj):
        if obj is None: return
        try:
            if self.opts.headers:
                setattr(obj, "extra_headers", self.opts.headers)
            setattr(obj, "timeout", self.opts.timeout)
            setattr(obj, "verbose", self.opts.verbose)
        except Exception:
            pass

    async def run(self):
        display_banner()
        legal_warning()
        print_info(f"Target: {self.opts.url}  Mode: {self.opts.mode}")

        try:
            if self.opts.mode in ("full", "recon"):
                await self.safe_run(self.phase_discovery(), "Discovery")

            if self.opts.mode in ("full", "auth"):
                await self.safe_run(self.phase_authentication(), "Authentication")

            if self.opts.mode in ("full", "enum"):
                await self.safe_run(self.phase_enumeration(), "Enumeration")

            # --- compute overall risk after all phases ---
            vulns = self.results.get("vulnerabilities", [])
            total_score = aggregate_target_score(vulns) if vulns else 0
            self.results["meta"]["risk_score"] = total_score
            self.results["meta"]["risk_label"] = map_severity_label(total_score)

            # generate report if requested
            self.generate_report()

        except KeyboardInterrupt:
            print_warning("Interrupted by user — saving partial results.")
        except Exception as e:
            print_error(f"Unhandled error during run: {e}")
        finally:
            self.results["meta"]["finished_at"] = datetime.utcnow().isoformat() + "Z"
            await self._shutdown()

    async def _shutdown(self):
        out_base = Path(self.opts.output) if self.opts.output else Path("graphql_crack_results")
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        json_file = out_base.with_suffix(f".{timestamp}.json") if self.opts.output else Path(f"graphql_crack_results.{timestamp}.json")
        try:
            if helpers_save_json(self.results, str(json_file)):
                print_success(f"Saved raw results → {json_file}")
        except Exception as e:
            print_error(f"Failed saving results: {e}")

    # ---------------- Phases ----------------
    async def phase_discovery(self):
        print_info("PHASE 1: Discovery")
        if not GraphQLDiscoverer:
            print_warning("Discovery module missing; skipping discovery phase.")
            return

        discoverer = GraphQLDiscoverer(self.opts.url)
        self._propagate(discoverer)
        endpoints = await self.safe_run(discoverer.discover_endpoints(), "discover_endpoints")
        endpoints = endpoints or []
        self.results["discovered_endpoints"] = endpoints
        print_success(f"Discovered {len(endpoints)} potential endpoints")

        # Quick introspection sampling (first N endpoints)
        sample = endpoints[:3]
        for ep in sample:
            if not IntrospectionAnalyzer:
                print_warning("IntrospectionAnalyzer missing; skipping introspection checks.")
                break
            print_info(f"Testing introspection on {ep}")
            analyzer = IntrospectionAnalyzer(ep)
            self._propagate(analyzer)
            intros = await self.safe_run(analyzer.get_introspection(), f"introspection:{ep}")
            if intros:
                finding = {
                    "type": "introspection_enabled",
                    "endpoint": ep,
                    "severity": "HIGH",
                    "description": "Introspection is enabled on this endpoint",
                    "exploitability": "moderate",
                    "exposure": "public",
                    "confidence": 0.85,
                }
                self.results["findings"].append(finding)
                self.results["vulnerabilities"].append(compute_risk_score(dict(finding)))

                # Schema analysis
                try:
                    schema_analysis = analyzer.analyze_schema(intros)
                except Exception as e:
                    schema_analysis = {}
                    self.results["errors"].append({"phase": "schema_analysis", "error": str(e)})
                self.results["schema_analysis"][ep] = schema_analysis

                sq = (schema_analysis or {}).get("sensitive_queries", [])
                if sq:
                    for item in sq[:25]:
                        vuln = {
                            "type": "sensitive_query",
                            "severity": "MEDIUM",
                            "description": f"Sensitive query field: {item.get('field') or item.get('name') or 'unknown'}",
                            "exploitability": "moderate",
                            "exposure": "public",
                            "confidence": 0.6,
                        }
                        self.results["vulnerabilities"].append(compute_risk_score(vuln))

    async def phase_authentication(self):
        print_info("PHASE 2: Authentication & JWT Testing")
        if not JWTBruteforcer:
            print_warning("JWTBruteforcer module missing; skipping authentication tests.")
            return

        bruteforcer = JWTBruteforcer(self.opts.url)
        self._propagate(bruteforcer)

        auth_ops = await self.safe_run(bruteforcer.discover_auth_endpoints(), "discover_auth_endpoints")
        self.results["auth_operations"] = auth_ops or []
        print_success(f"Auth ops probed: {len(self.results['auth_operations'])}")

        # JWT brute-force (optional)
        if self.opts.jwt_token:
            if not self.opts.wordlist:
                print_warning("No wordlist provided — skipping brute-force.")
            else:
                print_info("Starting JWT brute-force...")
                jwt_res = await self.safe_run(
                    bruteforcer.bruteforce_jwt(self.opts.jwt_token, self.opts.wordlist, threads=self.opts.threads),
                    "bruteforce_jwt",
                )
                self.results["jwt_analysis"] = jwt_res or {}
                if jwt_res and jwt_res.get("success"):
                    vuln = {
                        "type": "jwt_weak_secret",
                        "severity": "CRITICAL",
                        "description": f"JWT secret recovered: {jwt_res.get('secret')}",
                        "exploitability": "trivial",
                        "exposure": "public",
                        "confidence": 0.95,
                    }
                    self.results["vulnerabilities"].append(compute_risk_score(vuln))
                    print_success("JWT secret recovered!")

        # Run bypass tests
        bypass = await self.safe_run(bruteforcer.test_auth_bypass(), "test_auth_bypass")
        self.results["auth_bypass_tests"] = bypass or {}
        # Optional: treat successful bypass attempts as vulns with scores
        for name, outcome in (bypass or {}).items():
            ok = isinstance(outcome, dict) and outcome.get("success") is True
            if ok:
                vuln = {
                    "type": f"auth_bypass_{name}",
                    "severity": "HIGH",
                    "description": f"Authentication bypass technique succeeded: {name}",
                    "exploitability": "easy",
                    "exposure": "public",
                    "confidence": 0.8,
                }
                self.results["vulnerabilities"].append(compute_risk_score(vuln))

    async def phase_enumeration(self):
        print_info("PHASE 3: Schema Enumeration")
        if not SchemaEnumerator:
            print_warning("SchemaEnumerator missing; skipping enumeration.")
            return

        enumerator = SchemaEnumerator(self.opts.url)
        self._propagate(enumerator)
        schema = await self.safe_run(enumerator.enumerate_schema(), "enumerate_schema")
        self.results["enumerated_schema"] = schema or {}
        if not schema:
            print_warning("No schema discovered.")
            return

        # Counts
        queries_obj = schema.get("queries", {})
        mutations_obj = schema.get("mutations", {})
        q_count = len(queries_obj if isinstance(queries_obj, dict) else queries_obj or [])
        m_count = len(mutations_obj if isinstance(mutations_obj, dict) else mutations_obj or [])
        print_success(f"Discovered approx {q_count} queries, {m_count} mutations")

        # Sensitive ops: support both signatures
        sens = []
        try:
            if hasattr(enumerator, "detect_sensitive_operations"):
                try:
                    sens = enumerator.detect_sensitive_operations(schema)
                except TypeError:
                    sens = enumerator.detect_sensitive_operations()
            elif hasattr(enumerator, "find_sensitive_operations"):
                try:
                    sens = enumerator.find_sensitive_operations(schema)
                except TypeError:
                    sens = enumerator.find_sensitive_operations()
        except Exception as e:
            self.results["errors"].append({"phase": "sensitive_ops", "error": str(e)})
            sens = []

        if sens:
            for s in sens:
                # normalize
                op = (s.get("operation") or s.get("field") or "unknown")
                risk = s.get("risk", "info_disclosure")
                sev = s.get("severity") or {"auth": "HIGH", "dangerous_mutations": "CRITICAL", "info_disclosure": "MEDIUM"}.get(risk, "LOW")
                vuln = {
                    "type": f"schema_{risk}",
                    "severity": sev,
                    "description": f"Sensitive operation: {op}",
                    "exploitability": "moderate",
                    "exposure": "public",
                    "confidence": 0.6,
                }
                self.results["vulnerabilities"].append(compute_risk_score(vuln))
            print_success(f"Flagged {len(sens)} sensitive operations")

    # Report generation (HTML + JSON) if ReportGenerator available
    def generate_report(self):
        out_path = self.opts.output
        if not out_path:
            print_info("No output path specified; skipping HTML report generation.")
            return None

        if not ReportGenerator:
            print_warning("ReportGenerator not available. Saving raw JSON instead.")
            if helpers_save_json(self.results, out_path + ".json"):
                print_success(f"Saved raw JSON report to {out_path}.json")
            return None

        try:
            reporter = ReportGenerator(self.results)
            html_path = reporter.generate_html_report(out_path)
            print_success(f"HTML report generated: {html_path}")
            helpers_save_json(self.results, Path(out_path).with_suffix(".json"))
            return html_path
        except Exception as e:
            print_error(f"Failed to generate HTML report: {e}")
            helpers_save_json(self.results, out_path + ".json")
            return None

# ---- CLI entrypoint ----
def cli(argv=None):
    parser = argparse.ArgumentParser(description="GraphQL Crack Engine - Advanced GraphQL Security Assessment")
    parser.add_argument("-u", "--url", required=True, help="Target GraphQL endpoint base URL (e.g. https://api.target.com)")
    parser.add_argument("-m", "--mode", required=True, choices=["full", "recon", "auth", "enum"], help="Assessment mode")
    parser.add_argument("--jwt-token", help="JWT token to attempt brute-force on")
    parser.add_argument("--wordlist", help="Path to JWT secrets wordlist")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Threads for brute-force")
    parser.add_argument("-o", "--output", help="Output file path (HTML report path; JSON saved next to it)")
    parser.add_argument("--headers", help='Custom headers JSON string, e.g. \'{"Authorization":"Bearer X"}\'')
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode (debug logging)")
    args = parser.parse_args(argv)

    # parse headers JSON safely
    headers = None
    if args.headers:
        try:
            headers = json.loads(args.headers)
            if not isinstance(headers, dict):
                raise ValueError("headers must be a JSON object")
        except Exception as e:
            print_error(f"Invalid --headers JSON: {e}")
            sys.exit(2)

    opts = EngineOptions(
        url=args.url,
        mode=args.mode,
        jwt_token=args.jwt_token,
        wordlist=args.wordlist,
        threads=args.threads,
        output=args.output,
        headers=headers,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    logger = setup_logging(opts.verbose)
    engine = GraphQLCrackEngine(opts, logger=logger)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(engine.run())
    except KeyboardInterrupt:
        print_warning("Interrupted by user (KeyboardInterrupt).")
        loop.run_until_complete(engine._shutdown())
        sys.exit(1)
    finally:
        loop.close()

if __name__ == "__main__":
    cli()