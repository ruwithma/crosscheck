"""
Proof of Concept Generator for IDOR Scanner.

Generates reproduction commands (curl) for detected vulnerabilities.
"""

import json
from shlex import quote
from typing import Dict, Optional

from .models import Vulnerability


class PoCGenerator:
    """Generates Proof of Concept commands for vulnerabilities."""
    
    @staticmethod
    def generate_curl(vulnerability: Vulnerability) -> str:
        """
        Generate a curl command to reproduce the vulnerability.
        
        Args:
            vulnerability: The detected vulnerability
            
        Returns:
            A curl command string
        """
        request_data = vulnerability.evidence.attack_request
        if not request_data:
            return "# Error: No attack request data available for PoC"
            
        url = request_data.get("url", str(vulnerability.endpoint))
        method = request_data.get("method", vulnerability.method.value)
        headers = request_data.get("headers", {})
        body = request_data.get("body")
        json_body = request_data.get("json")
        
        # Build command
        cmd = ["curl"]
        
        # Method
        if method.upper() != "GET":
            cmd.extend(["-X", method.upper()])
            
        # Headers
        for key, value in headers.items():
            # Skip content-length as curl adds it
            if key.lower() == "content-length":
                continue
            cmd.extend(["-H", f"{key}: {value}"])
            
        # Body
        if json_body:
            cmd.extend(["-d", PoCGenerator._shlex_quote(json.dumps(json_body))])
            if "Content-Type" not in headers:
                cmd.extend(["-H", "Content-Type: application/json"])
        elif body:
            if isinstance(body, dict): # For query params passed as body?
                 # Normally httpx 'data'
                 from urllib.parse import urlencode
                 cmd.extend(["-d", PoCGenerator._shlex_quote(urlencode(body))])
            else:
                 cmd.extend(["-d", PoCGenerator._shlex_quote(str(body))])
            
        # URL
        cmd.append(PoCGenerator._shlex_quote(url))
        
        return " ".join(cmd)
    
    @staticmethod
    def _shlex_quote(s: str) -> str:
        """Safe shell quoting."""
        return quote(s)
