import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


class EvidenceStore:
    """Manages storage of evidence artifacts with content-based hashing."""
    
    def __init__(self, base_dir: str):
        """
        Initialize evidence store.
        
        Args:
            base_dir: Base directory for storing evidence
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.requests_dir = self.base_dir / "requests"
        self.responses_dir = self.base_dir / "responses"
        self.curl_dir = self.base_dir / "curl"
        self.har_dir = self.base_dir / "har"
        self.manifest_dir = self.base_dir / "manifests"
        
        for directory in [self.requests_dir, self.responses_dir, self.curl_dir, 
                         self.har_dir, self.manifest_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            
        logger.info(f"Evidence store initialized at {self.base_dir}")
        
    def store_request_response(self, 
                              request: httpx.Request,
                              response: httpx.Response,
                              metadata: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Store request and response data.
        
        Args:
            request: HTTP request object
            response: HTTP response object
            metadata: Additional metadata to store
            
        Returns:
            Dictionary with hashes and file paths
        """
        timestamp = datetime.utcnow().isoformat()
        
        # Prepare request data
        request_data = {
            'timestamp': timestamp,
            'method': request.method,
            'url': str(request.url),
            'headers': dict(request.headers),
            'body': request.content.decode('utf-8', errors='ignore') if request.content else None,
            'metadata': metadata or {}
        }
        
        # Prepare response data
        response_data = {
            'timestamp': timestamp,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body': response.text,
            'elapsed_ms': response.elapsed.total_seconds() * 1000,
            'metadata': metadata or {}
        }
        
        # Generate hashes
        request_hash = self._generate_hash(json.dumps(request_data, sort_keys=True))
        response_hash = self._generate_hash(json.dumps(response_data, sort_keys=True))
        
        # Store files
        request_file = self.requests_dir / f"{request_hash}.json"
        response_file = self.responses_dir / f"{response_hash}.json"
        
        with open(request_file, 'w') as f:
            json.dump(request_data, f, indent=2)
            
        with open(response_file, 'w') as f:
            json.dump(response_data, f, indent=2)
            
        logger.debug(f"Stored request/response: {request_hash}/{response_hash}")
        
        return {
            'request_hash': request_hash,
            'response_hash': response_hash,
            'request_file': str(request_file),
            'response_file': str(response_file)
        }
        
    def store_curl_command(self, 
                          request: httpx.Request,
                          metadata: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Generate and store a curl command for a request.
        
        Args:
            request: HTTP request object
            metadata: Additional metadata
            
        Returns:
            Dictionary with hash and file path
        """
        curl_command = self._generate_curl_command(request)
        
        curl_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'command': curl_command,
            'url': str(request.url),
            'method': request.method,
            'metadata': metadata or {}
        }
        
        curl_hash = self._generate_hash(curl_command)
        curl_file = self.curl_dir / f"{curl_hash}.json"
        
        with open(curl_file, 'w') as f:
            json.dump(curl_data, f, indent=2)
            
        logger.debug(f"Stored curl command: {curl_hash}")
        
        return {
            'curl_hash': curl_hash,
            'curl_file': str(curl_file),
            'command': curl_command
        }
        
    def store_har_entry(self,
                       request: httpx.Request,
                       response: httpx.Response,
                       metadata: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Store a HAR (HTTP Archive) entry.
        
        Args:
            request: HTTP request object
            response: HTTP response object
            metadata: Additional metadata
            
        Returns:
            Dictionary with hash and file path
        """
        # Create HAR entry format
        har_entry = {
            'startedDateTime': datetime.utcnow().isoformat() + 'Z',
            'time': response.elapsed.total_seconds() * 1000,
            'request': {
                'method': request.method,
                'url': str(request.url),
                'httpVersion': 'HTTP/1.1',
                'headers': [{'name': k, 'value': v} for k, v in request.headers.items()],
                'queryString': [],  # TODO: Parse query string
                'postData': {
                    'mimeType': request.headers.get('content-type', ''),
                    'text': request.content.decode('utf-8', errors='ignore') if request.content else ''
                },
                'bodySize': len(request.content) if request.content else 0
            },
            'response': {
                'status': response.status_code,
                'statusText': response.reason_phrase,
                'httpVersion': 'HTTP/1.1',
                'headers': [{'name': k, 'value': v} for k, v in response.headers.items()],
                'content': {
                    'size': len(response.content),
                    'mimeType': response.headers.get('content-type', ''),
                    'text': response.text
                },
                'bodySize': len(response.content)
            },
            'cache': {},
            'timings': {
                'send': 0,
                'wait': response.elapsed.total_seconds() * 1000,
                'receive': 0
            },
            'metadata': metadata or {}
        }
        
        har_hash = self._generate_hash(json.dumps(har_entry, sort_keys=True))
        har_file = self.har_dir / f"{har_hash}.json"
        
        with open(har_file, 'w') as f:
            json.dump(har_entry, f, indent=2)
            
        logger.debug(f"Stored HAR entry: {har_hash}")
        
        return {
            'har_hash': har_hash,
            'har_file': str(har_file)
        }
        
    def create_manifest(self, 
                       scan_id: str,
                       evidence_entries: List[Dict[str, Any]]) -> str:
        """
        Create a manifest file linking all evidence for a scan.
        
        Args:
            scan_id: Unique identifier for the scan
            evidence_entries: List of evidence entries with hashes and metadata
            
        Returns:
            Path to the manifest file
        """
        manifest = {
            'scan_id': scan_id,
            'created_at': datetime.utcnow().isoformat(),
            'evidence_count': len(evidence_entries),
            'evidence': evidence_entries,
            'base_dir': str(self.base_dir)
        }
        
        manifest_file = self.manifest_dir / f"{scan_id}.json"
        
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
            
        logger.info(f"Created evidence manifest: {manifest_file}")
        
        return str(manifest_file)
        
    def _generate_hash(self, content: str) -> str:
        """Generate SHA-256 hash of content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
        
    def _generate_curl_command(self, request: httpx.Request) -> str:
        """
        Generate a curl command equivalent to the HTTP request.
        
        Args:
            request: HTTP request object
            
        Returns:
            curl command string
        """
        parts = ['curl']
        
        # Add method
        if request.method != 'GET':
            parts.extend(['-X', request.method])
            
        # Add headers
        for name, value in request.headers.items():
            parts.extend(['-H', f"'{name}: {value}'"])
            
        # Add body data
        if request.content:
            body = request.content.decode('utf-8', errors='ignore')
            parts.extend(['-d', f"'{body}'"])
            
        # Add URL (always last)
        parts.append(f"'{request.url}'")
        
        return ' '.join(parts)
        
    def get_evidence_by_hash(self, evidence_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve evidence by hash.
        
        Args:
            evidence_hash: Hash of the evidence to retrieve
            
        Returns:
            Evidence data or None if not found
        """
        # Check all evidence directories
        for directory in [self.requests_dir, self.responses_dir, self.curl_dir, self.har_dir]:
            evidence_file = directory / f"{evidence_hash}.json"
            if evidence_file.exists():
                try:
                    with open(evidence_file, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    logger.error(f"Failed to load evidence {evidence_hash}: {e}")
                    
        return None
        
    def list_manifests(self) -> List[str]:
        """
        List all available manifest files.
        
        Returns:
            List of manifest file paths
        """
        return [str(f) for f in self.manifest_dir.glob("*.json")]
