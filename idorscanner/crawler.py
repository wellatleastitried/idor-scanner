import asyncio
import logging
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from .utils.http import HttpSession
from .utils.parser import extract_links_from_html, extract_forms_from_html, extract_endpoints_from_js
from .config import ScanConfig
from .identities import IdentityManager, SessionCapsule

logger = logging.getLogger(__name__)


@dataclass
class Endpoint:
    """Represents a discovered API endpoint."""
    method: str
    url_template: str
    params: Dict[str, Any]
    source: str  # 'html', 'js', 'form', 'manual'
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert endpoint to dictionary."""
        return {
            'method': self.method,
            'url_template': self.url_template,
            'params': self.params,
            'source': self.source,
            'metadata': self.metadata
        }


class EndpointCatalog:
    """Manages discovered endpoints."""
    
    def __init__(self):
        """Initialize endpoint catalog."""
        self.endpoints: List[Endpoint] = []
        self.discovered_urls: Set[str] = set()
        
    def add_endpoint(self, endpoint: Endpoint):
        """Add an endpoint to the catalog."""
        # Avoid duplicates
        for existing in self.endpoints:
            if (existing.method == endpoint.method and 
                existing.url_template == endpoint.url_template):
                return
                
        self.endpoints.append(endpoint)
        logger.debug(f"Added endpoint: {endpoint.method} {endpoint.url_template}")
        
    def get_endpoints_by_method(self, method: str) -> List[Endpoint]:
        """Get all endpoints for a specific HTTP method."""
        return [ep for ep in self.endpoints if ep.method.upper() == method.upper()]
        
    def get_all_endpoints(self) -> List[Endpoint]:
        """Get all discovered endpoints."""
        return self.endpoints.copy()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert catalog to dictionary."""
        return {
            'endpoint_count': len(self.endpoints),
            'endpoints': [ep.to_dict() for ep in self.endpoints],
            'discovered_urls_count': len(self.discovered_urls)
        }


class WebCrawler:
    """Discovers endpoints through web crawling and analysis."""
    
    def __init__(self, config: ScanConfig, identity_manager: IdentityManager):
        """
        Initialize web crawler.
        
        Args:
            config: Scan configuration
            identity_manager: Identity manager for authenticated crawling
        """
        self.config = config
        self.identity_manager = identity_manager
        self.catalog = EndpointCatalog()
        self.visited_urls: Set[str] = set()
        self.pending_urls: Set[str] = set()
        
        # Initialize with configured domains
        for domain in config.domains:
            if not domain.startswith(('http://', 'https://')):
                domain = f"https://{domain}"
            self.pending_urls.add(domain)
            
    async def crawl(self, max_depth: Optional[int] = None) -> EndpointCatalog:
        """
        Perform web crawling to discover endpoints.
        
        Args:
            max_depth: Maximum crawling depth (uses config default if None)
            
        Returns:
            EndpointCatalog with discovered endpoints
        """
        max_depth = max_depth or self.config.options.max_depth
        
        logger.info(f"Starting web crawl with max depth {max_depth}")
        
        for depth in range(max_depth):
            if not self.pending_urls:
                break
                
            logger.info(f"Crawling depth {depth + 1}/{max_depth}")
            
            # Process current level URLs
            current_urls = list(self.pending_urls)
            self.pending_urls.clear()
            
            # Use semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(self.config.options.max_concurrent)
            
            tasks = []
            for url in current_urls:
                if url not in self.visited_urls:
                    task = self._crawl_url_with_semaphore(semaphore, url)
                    tasks.append(task)
                    
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                
        logger.info(f"Crawl completed. Found {len(self.catalog.endpoints)} endpoints")
        return self.catalog
        
    async def _crawl_url_with_semaphore(self, semaphore: asyncio.Semaphore, url: str):
        """Crawl a URL with semaphore for concurrency control."""
        async with semaphore:
            await self._crawl_url(url)
            
    async def _crawl_url(self, url: str):
        """
        Crawl a single URL to discover endpoints.
        
        Args:
            url: URL to crawl
        """
        if url in self.visited_urls:
            return
            
        if not self._is_url_in_scope(url):
            logger.debug(f"URL out of scope: {url}")
            return
            
        self.visited_urls.add(url)
        logger.debug(f"Crawling: {url}")
        
        # Try crawling with different identities
        for identity_name in [session.identity_name for session in self.identity_manager.sessions.values()]:
            session = await self.identity_manager.get_session(identity_name)
            if session and session.session:
                try:
                    await self._crawl_url_with_session(url, session)
                    break  # Success with this identity
                except Exception as e:
                    logger.warning(f"Failed to crawl {url} with {identity_name}: {e}")
                    
    async def _crawl_url_with_session(self, url: str, session: SessionCapsule):
        """
        Crawl a URL using a specific session.
        
        Args:
            url: URL to crawl
            session: Session to use for the request
        """
        try:
            response = await session.session.get(url)
            
            if response.status_code >= 400:
                logger.debug(f"HTTP {response.status_code} for {url}")
                return
                
            content_type = response.headers.get('content-type', '').lower()
            
            if 'html' in content_type:
                await self._process_html_response(url, response.text)
            elif 'javascript' in content_type or 'json' in content_type:
                await self._process_js_response(url, response.text)
                
        except Exception as e:
            logger.warning(f"Error crawling {url}: {e}")
            
    async def _process_html_response(self, base_url: str, html_content: str):
        """
        Process HTML response to extract links and forms.
        
        Args:
            base_url: Base URL for resolving relative links
            html_content: HTML content to process
        """
        # Extract links
        links = extract_links_from_html(html_content, base_url)
        for link in links:
            if self._is_url_in_scope(link):
                self.pending_urls.add(link)
                
                # Add as GET endpoint
                endpoint = Endpoint(
                    method='GET',
                    url_template=link,
                    params={},
                    source='html',
                    metadata={'discovered_from': base_url}
                )
                self.catalog.add_endpoint(endpoint)
                
        # Extract forms
        forms = extract_forms_from_html(html_content, base_url)
        for form in forms:
            if self._is_url_in_scope(form['action']):
                # Add form action URL to pending
                self.pending_urls.add(form['action'])
                
                # Create endpoint for form submission
                endpoint = Endpoint(
                    method=form['method'],
                    url_template=form['action'],
                    params={inp['name']: inp.get('value', '') for inp in form['inputs'] if inp['name']},
                    source='form',
                    metadata={
                        'discovered_from': base_url,
                        'form_inputs': form['inputs']
                    }
                )
                self.catalog.add_endpoint(endpoint)
                
    async def _process_js_response(self, base_url: str, js_content: str):
        """
        Process JavaScript response to extract API endpoints.
        
        Args:
            base_url: Base URL for resolving relative endpoints
            js_content: JavaScript content to process
        """
        endpoints = extract_endpoints_from_js(js_content, base_url)
        
        for endpoint_url in endpoints:
            if self._is_url_in_scope(endpoint_url):
                self.pending_urls.add(endpoint_url)
                
                # Try to infer HTTP method from URL patterns
                methods = self._infer_methods_from_url(endpoint_url)
                
                for method in methods:
                    endpoint = Endpoint(
                        method=method,
                        url_template=endpoint_url,
                        params={},
                        source='js',
                        metadata={'discovered_from': base_url}
                    )
                    self.catalog.add_endpoint(endpoint)
                    
    def _is_url_in_scope(self, url: str) -> bool:
        """
        Check if URL is in scope for crawling.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is in scope
        """
        try:
            parsed = urlparse(url)
            
            # Check domain
            if parsed.netloc not in self.config.domains:
                return False
                
            # Check path against allow/deny lists
            path = parsed.path
            
            # Check deny list first
            for deny_pattern in self.config.paths.deny:
                if path.startswith(deny_pattern):
                    return False
                    
            # Check allow list
            if self.config.paths.allow:
                for allow_pattern in self.config.paths.allow:
                    if path.startswith(allow_pattern):
                        return True
                return False  # Not in allow list
                
            return True  # No allow list, just avoid deny list
            
        except Exception:
            return False
            
    def _infer_methods_from_url(self, url: str) -> List[str]:
        """
        Infer likely HTTP methods from URL patterns.
        
        Args:
            url: URL to analyze
            
        Returns:
            List of likely HTTP methods
        """
        url_lower = url.lower()
        
        # API patterns that suggest specific methods
        if '/api/' in url_lower:
            return ['GET', 'POST', 'PUT', 'DELETE']
        elif any(keyword in url_lower for keyword in ['create', 'new', 'add']):
            return ['POST']
        elif any(keyword in url_lower for keyword in ['update', 'edit', 'modify']):
            return ['PUT', 'PATCH']
        elif any(keyword in url_lower for keyword in ['delete', 'remove']):
            return ['DELETE']
        else:
            return ['GET']
            
    async def add_manual_endpoints(self, endpoints: List[Dict[str, Any]]):
        """
        Add manually specified endpoints to the catalog.
        
        Args:
            endpoints: List of endpoint dictionaries
        """
        for ep_data in endpoints:
            endpoint = Endpoint(
                method=ep_data.get('method', 'GET').upper(),
                url_template=ep_data['url'],
                params=ep_data.get('params', {}),
                source='manual',
                metadata=ep_data.get('metadata', {})
            )
            self.catalog.add_endpoint(endpoint)
            
        logger.info(f"Added {len(endpoints)} manual endpoints")
        
    async def discover_api_endpoints(self, base_url: str) -> List[Endpoint]:
        """
        Attempt to discover API endpoints through common patterns.
        
        Args:
            base_url: Base URL to check for API endpoints
            
        Returns:
            List of discovered API endpoints
        """
        common_api_paths = [
            '/api/v1/',
            '/api/v2/',
            '/api/',
            '/rest/',
            '/graphql',
            '/swagger.json',
            '/openapi.json',
            '/.well-known/openid_configuration'
        ]
        
        discovered = []
        
        # Try to get first available session
        session = None
        for session_capsule in self.identity_manager.sessions.values():
            if session_capsule.session:
                session = session_capsule
                break
                
        if not session:
            logger.warning("No session available for API discovery")
            return discovered
            
        for path in common_api_paths:
            try:
                test_url = urljoin(base_url, path)
                if not test_url.startswith(('http://', 'https://')):
                    test_url = urljoin('https://' + base_url if not base_url.startswith('http') else base_url, path)
                response = await session.session.get(test_url)
                
                if response.status_code < 400:
                    endpoint = Endpoint(
                        method='GET',
                        url_template=test_url,
                        params={},
                        source='api_discovery',
                        metadata={'status_code': response.status_code}
                    )
                    discovered.append(endpoint)
                    self.catalog.add_endpoint(endpoint)
                    
            except Exception as e:
                logger.debug(f"API discovery failed for {test_url}: {e}")
                
        logger.info(f"API discovery found {len(discovered)} endpoints")
        return discovered
        
    # TODO: Implement proxy capture mode for mitmproxy integration
    async def start_proxy_capture(self, proxy_port: int = 8080):
        """
        Start proxy capture mode (placeholder for mitmproxy integration).
        
        Args:
            proxy_port: Port to run the proxy on
        """
        logger.warning("Proxy capture mode not implemented yet")
        # TODO: Integrate with mitmproxy to capture traffic
        # This would involve:
        # 1. Starting mitmproxy on specified port
        # 2. Configuring it to log all requests/responses
        # 3. Parsing the captured traffic to extract endpoints
        # 4. Adding discovered endpoints to the catalog
