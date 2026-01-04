"""
Session Manager for the IDOR Scanner.

Handles multiple authenticated user sessions simultaneously,
supporting various authentication methods (Bearer, Basic, Cookie, API Key).
"""

import base64
import logging
from datetime import datetime
from typing import Any, Dict, Optional

import httpx

from .http_client import HTTPClient
from .models import AuthType, Session, UserCredentials

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class SessionManager:
    """
    Manages multiple authenticated user sessions.
    
    Features:
    - Support for multiple authentication types
    - Automatic token extraction from responses
    - Session isolation (no cross-contamination)
    - Auto-refresh for expired tokens
    - Parallel request handling with different sessions
    """
    
    def __init__(self, http_client: HTTPClient, auth_endpoint: Optional[str] = None):
        """
        Initialize the session manager.
        
        Args:
            http_client: The HTTP client to use for requests
            auth_endpoint: Default authentication endpoint (can be overridden per user)
        """
        self.http_client = http_client
        self.auth_endpoint = auth_endpoint
        self.sessions: Dict[str, Session] = {}
    
    async def authenticate(
        self,
        user_id: str,
        credentials: UserCredentials,
        auth_endpoint: Optional[str] = None,
    ) -> Session:
        """
        Authenticate a user and create a session.
        
        Args:
            user_id: Unique identifier for this user session
            credentials: User credentials for authentication
            auth_endpoint: Optional override for the auth endpoint
            
        Returns:
            Session object with authentication tokens
            
        Raises:
            AuthenticationError: If authentication fails
        """
        endpoint = auth_endpoint or credentials.auth_endpoint or self.auth_endpoint
        
        if not endpoint and credentials.auth_type != AuthType.NONE:
            # Try common auth endpoints
            endpoint = "/api/login"
        
        logger.info(f"Authenticating user: {user_id} ({credentials.role})")
        
        if credentials.auth_type == AuthType.NONE:
            # No authentication needed
            session = Session(
                user_id=user_id,
                role=credentials.role,
                credentials=credentials,
                auth_type=AuthType.NONE,
            )
        elif credentials.auth_type == AuthType.BASIC:
            # HTTP Basic Auth - encode credentials
            session = await self._basic_auth(user_id, credentials)
        elif credentials.auth_type == AuthType.BEARER:
            # Bearer token - login to get token
            session = await self._bearer_auth(user_id, credentials, endpoint)
        elif credentials.auth_type == AuthType.COOKIE:
            # Cookie-based auth
            session = await self._cookie_auth(user_id, credentials, endpoint)
        elif credentials.auth_type == AuthType.API_KEY:
            # API key auth
            session = await self._api_key_auth(user_id, credentials)
        else:
            raise AuthenticationError(f"Unsupported auth type: {credentials.auth_type}")
        
        self.sessions[user_id] = session
        logger.info(f"Successfully authenticated: {user_id}")
        return session
    
    async def _basic_auth(self, user_id: str, credentials: UserCredentials) -> Session:
        """Create session with HTTP Basic authentication."""
        # Encode credentials
        auth_string = f"{credentials.username}:{credentials.password}"
        token = base64.b64encode(auth_string.encode()).decode()
        
        return Session(
            user_id=user_id,
            role=credentials.role,
            credentials=credentials,
            auth_type=AuthType.BASIC,
            token=token,
            headers=credentials.extra_headers,
        )
    
    async def _bearer_auth(
        self, 
        user_id: str, 
        credentials: UserCredentials, 
        endpoint: str
    ) -> Session:
        """Authenticate and get Bearer token."""
        try:
            # Try email first (for Juice Shop and similar), then username
            response = await self.http_client.post(
                endpoint,
                json={
                    "email": credentials.username,
                    "password": credentials.password,
                },
            )
            
            # If email doesn't work, try username
            if response.status_code == 401:
                response = await self.http_client.post(
                    endpoint,
                    json={
                        "username": credentials.username,
                        "password": credentials.password,
                    },
                )
            
            if response.status_code not in (200, 201):
                raise AuthenticationError(
                    f"Login failed for {user_id}: {response.status_code} - {response.text}"
                )
            
            # Try to extract token from response
            data = response.json()
            token = self._extract_token(data)
            
            if not token:
                raise AuthenticationError(f"No token found in response for {user_id}")
            
            return Session(
                user_id=user_id,
                role=credentials.role,
                credentials=credentials,
                auth_type=AuthType.BEARER,
                token=token,
                headers=credentials.extra_headers,
            )
            
        except httpx.HTTPError as e:
            raise AuthenticationError(f"HTTP error during authentication: {e}")
    
    async def _cookie_auth(
        self, 
        user_id: str, 
        credentials: UserCredentials, 
        endpoint: str
    ) -> Session:
        """Authenticate and get session cookies."""
        try:
            response = await self.http_client.post(
                endpoint,
                json={
                    "username": credentials.username,
                    "password": credentials.password,
                },
            )
            
            if response.status_code not in (200, 201, 302):
                raise AuthenticationError(
                    f"Login failed for {user_id}: {response.status_code}"
                )
            
            # Extract cookies
            cookies = dict(response.cookies)
            
            return Session(
                user_id=user_id,
                role=credentials.role,
                credentials=credentials,
                auth_type=AuthType.COOKIE,
                cookies=cookies,
                headers=credentials.extra_headers,
            )
            
        except httpx.HTTPError as e:
            raise AuthenticationError(f"HTTP error during authentication: {e}")
    
    async def _api_key_auth(self, user_id: str, credentials: UserCredentials) -> Session:
        """Create session with API key authentication."""
        # Password field contains the API key
        return Session(
            user_id=user_id,
            role=credentials.role,
            credentials=credentials,
            auth_type=AuthType.API_KEY,
            token=credentials.password,  # API key stored in password field
            headers=credentials.extra_headers,
        )
    
    def _extract_token(self, data: Dict[str, Any]) -> Optional[str]:
        """
        Extract authentication token from response.
        
        Tries common field names for tokens.
        """
        token_fields = [
            "token",
            "access_token",
            "accessToken",
            "auth_token",
            "authToken",
            "jwt",
            "id_token",
            "bearer",
        ]
        
        # Check top-level fields
        for field in token_fields:
            if field in data:
                return str(data[field])
        
        # Check nested 'data' object
        if "data" in data and isinstance(data["data"], dict):
            for field in token_fields:
                if field in data["data"]:
                    return str(data["data"][field])
        
        # Check nested 'authentication' object
        if "authentication" in data and isinstance(data["authentication"], dict):
            for field in token_fields:
                if field in data["authentication"]:
                    return str(data["authentication"][field])
        
        return None
    
    async def refresh_if_needed(self, session: Session) -> Session:
        """
        Refresh the session token if expired.
        
        Args:
            session: The session to check and potentially refresh
            
        Returns:
            Updated session (may be the same if not expired)
        """
        if not session.is_expired():
            return session
        
        logger.info(f"Refreshing expired session for: {session.user_id}")
        
        # Re-authenticate
        new_session = await self.authenticate(
            session.user_id,
            session.credentials,
        )
        
        return new_session
    
    async def make_request(
        self,
        session: Session,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """
        Make an authenticated request using a specific session.
        
        Args:
            session: The session to use for authentication
            method: HTTP method
            url: Target URL
            **kwargs: Additional arguments to pass to the HTTP client
            
        Returns:
            httpx.Response object
        """
        # Refresh session if needed
        session = await self.refresh_if_needed(session)
        
        # Merge headers
        headers = kwargs.pop("headers", {})
        headers.update(session.get_auth_headers())
        
        # Merge cookies
        cookies = kwargs.pop("cookies", {})
        cookies.update(session.cookies)
        
        # Make request
        response = await self.http_client.request(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            **kwargs,
        )
        
        # Update last used timestamp
        session.last_used = datetime.now()
        
        return response
    
    def get_session(self, user_id: str) -> Optional[Session]:
        """Get a session by user ID."""
        return self.sessions.get(user_id)
    
    def list_sessions(self) -> list[str]:
        """List all active session user IDs."""
        return list(self.sessions.keys())
