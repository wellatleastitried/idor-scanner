import base64
import logging
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
from .utils.http import HttpSession
from .config import IdentityConfig

logger = logging.getLogger(__name__)


@dataclass
class SessionCapsule:
    """Container for session authentication data."""
    identity_name: str
    auth_type: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    credentials: Dict[str, Any]
    session: Optional[HttpSession] = None
    
    def __post_init__(self):
        """Initialize headers and cookies as empty dicts if None."""
        if self.headers is None:
            self.headers = {}
        if self.cookies is None:
            self.cookies = {}


class IdentityManager:
    """Manages multiple authenticated sessions for IDOR testing."""
    
    def __init__(self):
        """Initialize the identity manager."""
        self.sessions: Dict[str, SessionCapsule] = {}
        logger.info("Identity manager initialized")
        
    async def create_session(self, identity_config: IdentityConfig, 
                           base_url: Optional[str] = None) -> SessionCapsule:
        """
        Create an authenticated session for an identity.
        
        Args:
            identity_config: Identity configuration
            base_url: Base URL for the application (used for login flows)
            
        Returns:
            SessionCapsule with authentication data
        """
        logger.info(f"Creating session for identity: {identity_config.name}")
        
        headers = {}
        cookies = {}
        
        if identity_config.auth_type == 'none':
            pass
            
        elif identity_config.auth_type == 'basic':
            username = identity_config.credentials.get('username', '')
            password = identity_config.credentials.get('password', '')
            
            if not username or not password:
                raise ValueError(f"Basic auth requires username and password for {identity_config.name}")
                
            # Create basic auth header
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers['Authorization'] = f"Basic {encoded_credentials}"
            
        elif identity_config.auth_type == 'bearer':
            token = identity_config.credentials.get('token', '')
            
            if not token:
                raise ValueError(f"Bearer auth requires token for {identity_config.name}")
                
            headers['Authorization'] = f"Bearer {token}"
            
        elif identity_config.auth_type == 'cookie':
            session_cookies = identity_config.credentials.get('cookies', {})
            cookies.update(session_cookies)
            
        else:
            raise ValueError(f"Unsupported auth type: {identity_config.auth_type}")
            
        # Create HTTP session with auth data
        http_session = HttpSession(
            headers=headers,
            cookies=cookies,
            timeout=15.0,
            verify_ssl=True,
            follow_redirects=True
        )
        
        session_capsule = SessionCapsule(
            identity_name=identity_config.name,
            auth_type=identity_config.auth_type,
            headers=headers,
            cookies=cookies,
            credentials=identity_config.credentials,
            session=http_session
        )
        
        # Store session
        self.sessions[identity_config.name] = session_capsule
        
        logger.info(f"Session created for {identity_config.name} with auth type {identity_config.auth_type}")
        
        return session_capsule
        
    async def authenticate_with_login_flow(self, 
                                         identity_config: IdentityConfig,
                                         login_url: str,
                                         login_data: Dict[str, str]) -> SessionCapsule:
        """
        Authenticate using a login form flow.
        
        Args:
            identity_config: Identity configuration
            login_url: URL of the login endpoint
            login_data: Form data for login (username, password, etc.)
            
        Returns:
            SessionCapsule with authentication data from login response
        """
        logger.info(f"Performing login flow for identity: {identity_config.name}")
        
        http_session = HttpSession()
        await http_session.start()
        
        try:
            response = await http_session.post(login_url, data=login_data)
            response.raise_for_status()
            
            cookies = {}
            if hasattr(response, 'cookies'):
                for cookie in response.cookies.jar:
                    cookies[cookie.name] = cookie.value
                    
            # Extract additional auth tokens from response body/headers
            auth_headers = {}
            
            # Check response headers for auth tokens
            response_headers = dict(response.headers)
            
            # Common JWT token headers
            jwt_header_names = [
                'authorization', 'x-auth-token', 'x-access-token', 
                'x-api-key', 'bearer-token', 'jwt-token'
            ]
            
            for header_name in jwt_header_names:
                if header_name in response_headers:
                    token_value = response_headers[header_name]
                    # Store the token in the format expected by APIs
                    if header_name.lower() == 'authorization':
                        auth_headers['Authorization'] = token_value
                    else:
                        # Use the original header name but with proper casing
                        auth_headers[header_name.title().replace('-', '-')] = token_value
                    logger.debug(f"Extracted {header_name} from response headers")
            
            # Common CSRF token headers
            csrf_header_names = [
                'x-csrf-token', 'x-xsrf-token', 'csrf-token', 'xsrf-token'
            ]
            
            for header_name in csrf_header_names:
                if header_name in response_headers:
                    token_value = response_headers[header_name]
                    auth_headers[header_name.title().replace('-', '-')] = token_value
                    logger.debug(f"Extracted {header_name} from response headers")
            
            # Check response body for tokens (if JSON)
            try:
                content_type = response_headers.get('content-type', '').lower()
                if 'application/json' in content_type:
                    response_data = response.json()
                    
                    # Common JWT token field names in JSON responses
                    jwt_field_names = [
                        'token', 'access_token', 'accessToken', 'jwt', 'authToken',
                        'bearer_token', 'bearerToken', 'api_key', 'apiKey'
                    ]
                    
                    for field_name in jwt_field_names:
                        if field_name in response_data:
                            token_value = response_data[field_name]
                            # Add Bearer prefix if not present and looks like JWT
                            if isinstance(token_value, str) and '.' in token_value:
                                if not token_value.startswith('Bearer '):
                                    token_value = f'Bearer {token_value}'
                                auth_headers['Authorization'] = token_value
                                logger.debug(f"Extracted JWT token from response body field: {field_name}")
                                break
                    
                    # Common CSRF token field names in JSON responses
                    csrf_field_names = [
                        'csrf_token', 'csrfToken', 'xsrf_token', 'xsrfToken',
                        '_token', 'authenticity_token'
                    ]
                    
                    for field_name in csrf_field_names:
                        if field_name in response_data:
                            token_value = response_data[field_name]
                            auth_headers['X-CSRF-Token'] = token_value
                            logger.debug(f"Extracted CSRF token from response body field: {field_name}")
                            break
                            
            except Exception as e:
                logger.debug(f"Failed to parse response body as JSON: {e}")
                # Not a JSON response or malformed JSON, continue with cookies only
            
            # Log summary of extracted authentication data
            auth_summary = []
            if cookies:
                auth_summary.append(f"{len(cookies)} cookies")
            if auth_headers:
                auth_summary.append(f"{len(auth_headers)} auth headers")
            
            if auth_summary:
                logger.info(f"Extracted authentication data for {identity_config.name}: {', '.join(auth_summary)}")
            else:
                logger.warning(f"No authentication tokens extracted for {identity_config.name}, using cookies only")
            
            # Create authenticated session capsule
            session_capsule = SessionCapsule(
                identity_name=identity_config.name,
                auth_type='cookie',  # Login flows typically use cookies
                headers=auth_headers,  # Include extracted auth tokens
                cookies=cookies,
                credentials=identity_config.credentials
            )
            
            # Create new session with authentication data
            auth_session = HttpSession(cookies=cookies, headers=auth_headers)
            session_capsule.session = auth_session
            
            # Store session
            self.sessions[identity_config.name] = session_capsule
            
            logger.info(f"Login successful for {identity_config.name}")
            
            return session_capsule
            
        except Exception as e:
            logger.error(f"Login failed for {identity_config.name}: {e}")
            raise
        finally:
            await http_session.close()
            
    async def get_session(self, identity_name: str) -> Optional[SessionCapsule]:
        """
        Get an existing session by identity name.
        
        Args:
            identity_name: Name of the identity
            
        Returns:
            SessionCapsule or None if not found
        """
        return self.sessions.get(identity_name)
        
    async def refresh_session(self, identity_name: str) -> Optional[SessionCapsule]:
        """
        Refresh an existing session (placeholder for token refresh logic).
        
        Args:
            identity_name: Name of the identity to refresh
            
        Returns:
            Refreshed SessionCapsule or None if not found
        """
        # TODO: Implement token refresh logic for JWT/OAuth tokens
        session = self.sessions.get(identity_name)
        if session:
            logger.info(f"Session refresh requested for {identity_name} (not implemented)")
        return session
        
    async def validate_session(self, identity_name: str, test_url: str) -> bool:
        """
        Validate that a session is still active by making a test request.
        
        Args:
            identity_name: Name of the identity to test
            test_url: URL to test authentication against
            
        Returns:
            True if session is valid, False otherwise
        """
        session = self.sessions.get(identity_name)
        if not session or not session.session:
            return False
            
        try:
            response = await session.session.get(test_url)
            # Consider 2xx and 3xx as valid (authenticated)
            # 401/403 would indicate invalid session
            is_valid = response.status_code < 400
            
            logger.debug(f"Session validation for {identity_name}: {response.status_code} -> {'valid' if is_valid else 'invalid'}")
            
            return is_valid
            
        except Exception as e:
            logger.warning(f"Session validation failed for {identity_name}: {e}")
            return False
            
    async def close_all_sessions(self):
        """Close all active HTTP sessions."""
        for identity_name, session in self.sessions.items():
            if session.session:
                try:
                    await session.session.close()
                    logger.debug(f"Closed session for {identity_name}")
                except Exception as e:
                    logger.warning(f"Error closing session for {identity_name}: {e}")
                    
        self.sessions.clear()
        logger.info("All sessions closed")
        
    def list_sessions(self) -> Dict[str, str]:
        """
        List all active sessions.
        
        Returns:
            Dictionary mapping identity names to auth types
        """
        return {name: session.auth_type for name, session in self.sessions.items()}
        
    async def create_playwright_session(self, identity_config: IdentityConfig) -> SessionCapsule:
        """
        Create a session using Playwright browser automation.
        
        Args:
            identity_config: Identity configuration
            
        Returns:
            SessionCapsule with browser-extracted authentication data
            
        Note:
            This is a stub for future Playwright integration
        """
        # TODO: Implement Playwright session creation
        # This would involve:
        # 1. Launching a browser instance
        # 2. Navigating to login page
        # 3. Filling and submitting login form
        # 4. Extracting cookies/tokens from authenticated session
        # 5. Converting to SessionCapsule for use with httpx
        
        logger.warning(f"Playwright session creation not implemented for {identity_config.name}")
        
        # Return a placeholder session for now
        return SessionCapsule(
            identity_name=identity_config.name,
            auth_type=identity_config.auth_type,
            headers={},
            cookies={},
            credentials=identity_config.credentials
        )
