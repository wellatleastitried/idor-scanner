"""
Wrapper around httpx for sessions, retries
"""

import asyncio
import logging
from typing import Dict, Any, Optional, Union
import httpx
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class HttpSession:
    """Wrapper around httpx.AsyncClient with retry logic and session management."""
    
    def __init__(self, 
                 timeout: float = 15.0,
                 verify_ssl: bool = True,
                 follow_redirects: bool = True,
                 headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None):
        """
        Initialize HTTP session.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            follow_redirects: Whether to follow HTTP redirects
            headers: Default headers to include in requests
            cookies: Default cookies to include in requests
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.default_headers = headers or {}
        self.default_cookies = cookies or {}
        self._client: Optional[httpx.AsyncClient] = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
        
    async def start(self):
        """Initialize the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                headers=self.default_headers,
                cookies=self.default_cookies
            )
        
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            
    async def request(self, 
                     method: str,
                     url: str,
                     headers: Optional[Dict[str, str]] = None,
                     data: Optional[Union[str, Dict[str, Any]]] = None,
                     json: Optional[Dict[str, Any]] = None,
                     params: Optional[Dict[str, str]] = None,
                     retries: int = 3,
                     backoff_factor: float = 1.0) -> httpx.Response:
        """
        Make an HTTP request with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Request headers
            data: Form data or raw body
            json: JSON data (will be serialized)
            params: URL parameters
            retries: Number of retry attempts
            backoff_factor: Exponential backoff factor
            
        Returns:
            httpx.Response object
            
        Raises:
            httpx.RequestError: If all retries fail
        """
        if not self._client:
            await self.start()
            
        merged_headers = {**self.default_headers}
        if headers:
            merged_headers.update(headers)
            
        last_exception = None
        
        for attempt in range(retries + 1):
            try:
                logger.debug(f"Making {method} request to {url} (attempt {attempt + 1})")
                
                response = await self._client.request(
                    method=method,
                    url=url,
                    headers=merged_headers,
                    data=data,
                    json=json,
                    params=params
                )
                
                logger.debug(f"Response: {response.status_code} for {method} {url}")
                return response
                
            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                last_exception = e
                logger.warning(f"Request failed (attempt {attempt + 1}): {e}")
                
                if attempt < retries:
                    wait_time = backoff_factor * (2 ** attempt)
                    logger.debug(f"Retrying in {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"All {retries + 1} attempts failed for {method} {url}")
                    
        raise last_exception
        
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make a GET request."""
        return await self.request('GET', url, **kwargs)
        
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Make a POST request."""
        return await self.request('POST', url, **kwargs)
        
    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Make a PUT request."""
        return await self.request('PUT', url, **kwargs)
        
    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Make a DELETE request."""
        return await self.request('DELETE', url, **kwargs)
        
    async def patch(self, url: str, **kwargs) -> httpx.Response:
        """Make a PATCH request."""
        return await self.request('PATCH', url, **kwargs)


@asynccontextmanager
async def create_session(**kwargs):
    """Create an HTTP session as an async context manager."""
    session = HttpSession(**kwargs)
    try:
        await session.start()
        yield session
    finally:
        await session.close()


async def _rate_limit(self):
        """Apply rate limiting."""
        # TODO: Implement proper rate limiting based on configuration
        await asyncio.sleep(0.1)
