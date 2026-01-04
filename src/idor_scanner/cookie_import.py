"""
Cookie Import Module for IDOR Scanner.

Supports importing cookies from various browser export formats:
- Cookie Editor extension (JSON format)
- Netscape/HTTP cookie format
- Raw cookie string
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ImportedCookie:
    """Represents an imported cookie."""
    name: str
    value: str
    domain: str
    path: str = "/"
    expires: Optional[datetime] = None
    secure: bool = False
    http_only: bool = False


class CookieImporter:
    """
    Import cookies from various browser export formats.
    
    Supports:
    - Cookie Editor extension JSON export
    - Netscape/Mozilla cookie format (cookies.txt)
    - Raw cookie string (name=value; name2=value2)
    - EditThisCookie extension JSON export
    """
    
    def __init__(self):
        self.cookies: Dict[str, str] = {}
    
    def import_from_file(self, file_path: str) -> Dict[str, str]:
        """
        Auto-detect format and import cookies from file.
        
        Args:
            file_path: Path to cookie file
            
        Returns:
            Dictionary of cookie name -> value
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Cookie file not found: {file_path}")
        
        content = path.read_text(encoding="utf-8")
        
        # Try to detect format
        if content.strip().startswith("[") or content.strip().startswith("{"):
            # JSON format (Cookie Editor, EditThisCookie)
            return self.import_from_json(content)
        elif content.startswith("# Netscape") or content.startswith("# HTTP"):
            # Netscape format
            return self.import_from_netscape(content)
        else:
            # Try as raw cookie string
            return self.import_from_string(content)
    
    def import_from_json(self, content: str) -> Dict[str, str]:
        """
        Import from JSON format (Cookie Editor, EditThisCookie).
        
        Handles both array format and object format.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON cookie format: {e}")
        
        cookies = {}
        
        # Handle array format (Cookie Editor)
        if isinstance(data, list):
            for cookie in data:
                name = cookie.get("name") or cookie.get("Name")
                value = cookie.get("value") or cookie.get("Value")
                if name and value:
                    cookies[name] = value
                    logger.debug(f"Imported cookie: {name}")
        
        # Handle object format
        elif isinstance(data, dict):
            # Check if it's a single cookie object
            if "name" in data or "Name" in data:
                name = data.get("name") or data.get("Name")
                value = data.get("value") or data.get("Value")
                if name and value:
                    cookies[name] = value
            # Or a dict of name: value
            else:
                for name, value in data.items():
                    if isinstance(value, str):
                        cookies[name] = value
                    elif isinstance(value, dict):
                        cookies[name] = value.get("value", str(value))
        
        logger.info(f"Imported {len(cookies)} cookies from JSON")
        self.cookies.update(cookies)
        return cookies
    
    def import_from_netscape(self, content: str) -> Dict[str, str]:
        """
        Import from Netscape/Mozilla cookies.txt format.
        
        Format: domain	flag	path	secure	expiry	name	value
        """
        cookies = {}
        
        for line in content.split("\n"):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            
            parts = line.split("\t")
            if len(parts) >= 7:
                name = parts[5]
                value = parts[6]
                cookies[name] = value
                logger.debug(f"Imported cookie: {name}")
        
        logger.info(f"Imported {len(cookies)} cookies from Netscape format")
        self.cookies.update(cookies)
        return cookies
    
    def import_from_string(self, cookie_string: str) -> Dict[str, str]:
        """
        Import from raw cookie string (name=value; name2=value2).
        
        This is the format from document.cookie or browser dev tools.
        """
        cookies = {}
        
        # Clean up the string
        cookie_string = cookie_string.strip()
        
        # Split by semicolon
        for part in cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                name = name.strip()
                value = value.strip()
                if name:
                    cookies[name] = value
                    logger.debug(f"Imported cookie: {name}")
        
        logger.info(f"Imported {len(cookies)} cookies from string")
        self.cookies.update(cookies)
        return cookies
    
    def to_cookie_header(self, filter_domain: Optional[str] = None) -> str:
        """
        Convert cookies to a Cookie header string.
        
        Args:
            filter_domain: Optional domain to filter cookies for
            
        Returns:
            Cookie header value (name=value; name2=value2)
        """
        return "; ".join(f"{name}={value}" for name, value in self.cookies.items())
    
    def to_dict(self) -> Dict[str, str]:
        """Return cookies as a dictionary."""
        return self.cookies.copy()
    
    def get_auth_tokens(self) -> Dict[str, str]:
        """
        Extract common authentication tokens from cookies.
        
        Returns dict with keys like 'access_token', 'session_id', 'user_id'.
        """
        auth_patterns = [
            "access_token",
            "token",
            "auth",
            "session",
            "user_id",
            "userid",
            "jwt",
            "bearer",
            "api_key",
            "apikey",
        ]
        
        auth_cookies = {}
        for name, value in self.cookies.items():
            name_lower = name.lower()
            for pattern in auth_patterns:
                if pattern in name_lower:
                    auth_cookies[name] = value
                    break
        
        return auth_cookies


def load_cookies_from_file(file_path: str) -> Dict[str, str]:
    """
    Convenience function to load cookies from a file.
    
    Args:
        file_path: Path to cookie file (JSON, Netscape, or raw string)
        
    Returns:
        Dictionary of cookie name -> value
    """
    importer = CookieImporter()
    return importer.import_from_file(file_path)


def parse_cookie_string(cookie_string: str) -> Dict[str, str]:
    """
    Convenience function to parse a raw cookie string.
    
    Args:
        cookie_string: Raw cookie string (from document.cookie)
        
    Returns:
        Dictionary of cookie name -> value
    """
    importer = CookieImporter()
    return importer.import_from_string(cookie_string)
