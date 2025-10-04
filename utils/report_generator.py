#!/usr/bin/env python3
"""
Report Generator for GraphQL Security Assessment
"""

import json
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, assessment_data):
        self.data = assessment_data
    
    def generate_html_report(self, output_file=None):
        """Generate HTML assessment report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"graphql_assessment_{timestamp}.html"
        
        html_content = self._generate_html_content()
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    def _generate_html_content(self):
        """Generate HTML content"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GraphQL Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        .section {{ margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }}
        .vulnerability {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; }}
        .critical {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .high {{ background: #ffeaa7; border-left: 4px solid #f39c12; }}
        .success {{ color: #28a745; }}
        .danger {{ color: #dc3545; }}
        .warning {{ color: #ffc107; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 GraphQL Security Assessment Report</h1>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Target: {self.data.get('target', 'N/A')}</p>
        </div>
        
        {self._generate_summary_section()}
        {self._generate_vulnerabilities_section()}
        {self._generate_findings_section()}
        {self._generate_technical_details()}
        {self._generate_legal_notice()}
    </div>
</body>
</html>
        """
    
    def _generate_summary_section(self):
        """Generate summary section"""
        vuln_count = len(self.data.get('vulnerabilities', []))
        findings_count = len(self.data.get('findings', []))
        
        return f"""
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <p><strong>Assessment Mode:</strong> {self.data.get('mode', 'N/A')}</p>
            <p><strong>Vulnerabilities Found:</strong> <span class="{'danger' if vuln_count > 0 else 'success'}">{vuln_count}</span></p>
            <p><strong>Security Findings:</strong> {findings_count}</p>
            <p><strong>Assessment Date:</strong> {datetime.now().strftime("%Y-%m-%d")}</p>
        </div>
        """
    
    def _generate_vulnerabilities_section(self):
        """Generate vulnerabilities section"""
        vulnerabilities = self.data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return """
            <div class="section">
                <h2>No Critical Vulnerabilities Found</h2>
                <p>No critical security vulnerabilities were identified during this assessment.</p>
            </div>
            """
        
        vuln_html = ""
        for vuln in vulnerabilities:
            severity_class = vuln.get('severity', '').lower()
            vuln_html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln.get('type', 'Unknown')}</h3>
                <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
                <p><strong>Impact:</strong> {vuln.get('impact', 'N/A')}</p>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>Security Vulnerabilities</h2>
            {vuln_html}
        </div>
        """
    
    def _generate_findings_section(self):
        """Generate findings section"""
        findings = self.data.get('findings', [])
        
        if not findings:
            return ""
        
        findings_html = ""
        for finding in findings:
            findings_html += f"""
            <div class="vulnerability">
                <h3>{finding.get('type', 'Unknown')}</h3>
                <p><strong>Endpoint:</strong> {finding.get('endpoint', 'N/A')}</p>
                <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
            </div>
            """
        
        return f"""
        <div class="section">
            <h2>🔍 Security Findings</h2>
            {findings_html}
        </div>
        """
    
    def _generate_technical_details(self):
        """Generate technical details section"""
        technical_data = {
            'Discovered Endpoints': self.data.get('discovered_endpoints', []),
            'JWT Analysis': self.data.get('jwt_analysis', {}),
            'Schema Analysis': self.data.get('schema_analysis', {})
        }
        
        technical_html = ""
        for key, value in technical_data.items():
            technical_html += f"""
            <h3>{key}</h3>
            <pre>{json.dumps(value, indent=2)}</pre>
            """
        
        return f"""
        <div class="section">
            <h2>Technical Details</h2>
            {technical_html}
        </div>
        """
    
    def _generate_legal_notice(self):
        """Generate legal notice"""
        return """
        <div class="section" style="background: #f8f9fa; border: 1px solid #dee2e6;">
            <h2>Legal Notice</h2>
            <p><strong>Educational Use Only:</strong> This report is generated for educational purposes and authorized security testing.</p>
            <p><strong>Authorization Required:</strong> Unauthorized testing is illegal and unethical.</p>
            <p><strong>Responsible Disclosure:</strong> Any vulnerabilities found should be responsibly disclosed to the appropriate parties.</p>
        </div>
        """