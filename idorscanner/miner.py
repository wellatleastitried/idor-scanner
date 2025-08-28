import re
import json
import logging
from typing import Dict, List, Set, Any, Optional, Union
from urllib.parse import urlparse
from .utils.parser import extract_ids_from_text, extract_ids_from_html

logger = logging.getLogger(__name__)


class IDMiner:
    """Extracts and classifies potential ID values from HTTP responses."""
    
    def __init__(self):
        """Initialize the ID miner with regex patterns."""
        self.patterns = {
            'uuid': re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.IGNORECASE),
            'numeric_id': re.compile(r'\b\d{3,}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'hash': re.compile(r'\b[a-f0-9]{32,}\b', re.IGNORECASE),
            'jwt': re.compile(r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
            'base64': re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b'),
            'hex': re.compile(r'\b0x[a-f0-9]{8,}\b', re.IGNORECASE),
            'slug': re.compile(r'\b[a-z0-9]+-[a-z0-9-]+\b'),
        }
        
    def mine_response(self, 
                     url: str, 
                     response_text: str, 
                     response_headers: Dict[str, str],
                     content_type: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Mine IDs from an HTTP response.
        
        Args:
            url: The response URL
            response_text: Response body text
            response_headers: Response headers
            content_type: Content type of the response
            
        Returns:
            Dictionary mapping ID types to lists of found IDs
        """
        logger.debug(f"Mining IDs from response: {url}")
        
        found_ids = {
            'path_params': [],
            'json_fields': [],
            'html_attributes': [],
            'text_content': [],
            'headers': []
        }
        
        found_ids['path_params'] = self._mine_path_params(url)
        
        found_ids['headers'] = self._mine_headers(response_headers)
        
        if content_type:
            content_type = content_type.lower()
            
        if content_type and 'json' in content_type:
            found_ids['json_fields'] = self._mine_json_content(response_text)
        elif content_type and 'html' in content_type:
            found_ids['html_attributes'] = self._mine_html_content(response_text)
            
        found_ids['text_content'] = self._mine_text_content(response_text)
        
        for key in found_ids:
            found_ids[key] = list(set(found_ids[key]))
            
        total_ids = sum(len(ids) for ids in found_ids.values())
        logger.debug(f"Found {total_ids} total IDs in {url}")
        
        return found_ids
        
    def _mine_path_params(self, url: str) -> List[str]:
        """Extract potential ID values from URL path parameters."""
        ids = []
        
        try:
            parsed = urlparse(url)
            path_segments = parsed.path.split('/')
            
            for segment in path_segments:
                if segment:  # Skip empty segments
                    # Check if segment matches any ID pattern
                    matched = False
                    for pattern_name, pattern in self.patterns.items():
                        if pattern.match(segment):
                            ids.append(segment)
                            matched = True
                            break
                    # Also check for pure numeric segments
                    if not matched and segment.isdigit() and len(segment) >= 3:
                        ids.append(segment)
                        
        except Exception as e:
            logger.warning(f"Failed to mine path params from {url}: {e}")
            
        return ids
        
    def _mine_json_content(self, response_text: str) -> List[str]:
        """Extract ID values from JSON response content."""
        ids = []
        
        try:
            data = json.loads(response_text)
            ids = self._extract_ids_from_json_recursive(data)
        except json.JSONDecodeError:
            logger.debug("Response is not valid JSON, skipping JSON mining")
        except Exception as e:
            logger.warning(f"Failed to mine JSON content: {e}")
            
        return ids
        
    def _extract_ids_from_json_recursive(self, data: Any, parent_key: str = '') -> List[str]:
        """Recursively extract IDs from JSON data structure."""
        ids = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                # Check if key suggests an ID field
                if self._is_id_field_name(key):
                    if isinstance(value, (str, int)):
                        ids.append(str(value))
                        
                # Recursively process nested structures
                ids.extend(self._extract_ids_from_json_recursive(value, key))
                
        elif isinstance(data, list):
            for item in data:
                ids.extend(self._extract_ids_from_json_recursive(item, parent_key))
                
        elif isinstance(data, (str, int)):
            # Check if value matches ID patterns
            value_str = str(data)
            for pattern in self.patterns.values():
                if pattern.match(value_str):
                    ids.append(value_str)
                    break
                    
        return ids
        
    def _mine_html_content(self, response_text: str) -> List[str]:
        """Extract ID values from HTML content."""
        try:
            return list(extract_ids_from_html(response_text))
        except Exception as e:
            logger.warning(f"Failed to mine HTML content: {e}")
            return []
            
    def _mine_text_content(self, response_text: str) -> List[str]:
        """Extract ID values from text using regex patterns."""
        try:
            return list(extract_ids_from_text(response_text))
        except Exception as e:
            logger.warning(f"Failed to mine text content: {e}")
            return []
            
    def _mine_headers(self, headers: Dict[str, str]) -> List[str]:
        """Extract potential ID values from response headers."""
        ids = []
        
        # Headers that commonly contain IDs
        id_headers = ['x-request-id', 'x-correlation-id', 'x-trace-id', 'x-session-id', 
                     'etag', 'location', 'x-user-id', 'x-tenant-id']
        
        for header_name, header_value in headers.items():
            if header_name.lower() in id_headers:
                # Extract IDs from header value
                for pattern in self.patterns.values():
                    matches = pattern.findall(header_value)
                    ids.extend(matches)
                    
        return ids
        
    def _is_id_field_name(self, field_name: str) -> bool:
        """Check if a field name suggests it contains an ID value."""
        field_name = field_name.lower()
        
        id_indicators = [
            'id', 'uuid', 'guid', 'key', 'token', 'hash', 'code',
            'user_id', 'userid', 'account_id', 'session_id', 'request_id',
            'tenant_id', 'organization_id', 'org_id', 'team_id', 'group_id',
            'product_id', 'order_id', 'transaction_id', 'payment_id',
            'customer_id', 'client_id', 'api_key', 'access_token'
        ]
        
        return any(indicator in field_name for indicator in id_indicators)
        
    def classify_ids(self, ids: List[str]) -> Dict[str, List[str]]:
        """
        Classify extracted IDs by their apparent type.
        
        Args:
            ids: List of ID strings to classify
            
        Returns:
            Dictionary mapping ID types to lists of IDs
        """
        classified = {
            'uuid': [],
            'numeric': [],
            'email': [],
            'hash': [],
            'jwt': [],
            'base64': [],
            'hex': [],
            'slug': [],
            'unknown': []
        }
        
        for id_value in ids:
            classified_type = self._classify_single_id(id_value)
            classified[classified_type].append(id_value)
            
        return classified
        
    def _classify_single_id(self, id_value: str) -> str:
        """Classify a single ID value by type."""
        for pattern_name, pattern in self.patterns.items():
            if pattern.match(id_value):
                return pattern_name
                
        # Special case for pure numeric IDs
        if id_value.isdigit():
            return 'numeric'
            
        return 'unknown'
        
    def find_related_ids(self, target_id: str, all_responses: List[Dict[str, Any]]) -> List[str]:
        """
        Find IDs that appear to be related to a target ID across multiple responses.
        
        Args:
            target_id: The ID to find relationships for
            all_responses: List of response dictionaries with mined IDs
            
        Returns:
            List of potentially related IDs
        """
        related_ids = set()
        
        for response in all_responses:
            response_ids = []
            for id_type, ids in response.get('mined_ids', {}).items():
                response_ids.extend(ids)
                
            # If target ID appears in this response, consider other IDs as related
            if target_id in response_ids:
                related_ids.update(response_ids)
                
        # Remove the target ID itself
        related_ids.discard(target_id)
        
        return list(related_ids)
        
    def suggest_mutations(self, id_value: str, related_ids: List[str] = None) -> List[str]:
        """
        Suggest potential mutations for an ID value.
        
        Args:
            id_value: The original ID value
            related_ids: List of related IDs for context
            
        Returns:
            List of suggested mutation values
        """
        mutations = []
        related_ids = related_ids or []
        
        id_type = self._classify_single_id(id_value)
        
        if id_type == 'numeric':
            # Numeric mutations
            try:
                num_value = int(id_value)
                mutations.extend([
                    str(num_value + 1),
                    str(num_value - 1),
                    str(num_value + 10),
                    str(num_value - 10),
                    '1',
                    '0',
                    '999999'
                ])
            except ValueError:
                pass
                
        elif id_type == 'uuid':
            # Use related UUIDs if available
            for related_id in related_ids:
                if self._classify_single_id(related_id) == 'uuid':
                    mutations.append(related_id)
                    
        elif id_type == 'slug':
            # Try common variations for slugs
            mutations.extend([
                id_value.replace('-', '_'),
                id_value + '-test',
                'admin-' + id_value,
                'test-' + id_value
            ])
            
        # Add some common test values regardless of type
        mutations.extend(['admin', 'test', 'guest', '1', '0'])
        
        # Add related IDs of the same type
        for related_id in related_ids:
            if self._classify_single_id(related_id) == id_type:
                mutations.append(related_id)
                
        return list(set(mutations))  # Remove duplicates
