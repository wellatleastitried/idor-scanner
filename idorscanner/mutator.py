import uuid
import logging
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass
from .miner import IDMiner

logger = logging.getLogger(__name__)


@dataclass
class MutatedRequest:
    """Represents a mutated request for IDOR testing."""
    original_url: str
    mutated_url: str
    method: str
    headers: Dict[str, str]
    body: Optional[str]
    params: Dict[str, str]
    mutation_type: str
    mutated_fields: Dict[str, Tuple[str, str]]  # field_name -> (original_value, mutated_value)
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'original_url': self.original_url,
            'mutated_url': self.mutated_url,
            'method': self.method,
            'headers': self.headers,
            'body': self.body,
            'params': self.params,
            'mutation_type': self.mutation_type,
            'mutated_fields': {k: {'original': v[0], 'mutated': v[1]} 
                             for k, v in self.mutated_fields.items()},
            'metadata': self.metadata
        }


class RequestMutator:
    """Generates mutated requests for IDOR vulnerability testing."""
    
    def __init__(self):
        """Initialize the request mutator."""
        self.id_miner = IDMiner()
        
    def generate_mutations(self, 
                          original_url: str,
                          method: str,
                          headers: Dict[str, str],
                          body: Optional[str],
                          identity_ids: Dict[str, List[str]],
                          discovered_ids: List[str] = None) -> List[MutatedRequest]:
        """
        Generate mutated requests for IDOR testing.
        
        Args:
            original_url: Original request URL
            method: HTTP method
            headers: Request headers
            body: Request body (if any)
            identity_ids: IDs associated with different identities
            discovered_ids: Additional IDs discovered during crawling
            
        Returns:
            List of mutated requests
        """
        logger.debug(f"Generating mutations for {method} {original_url}")
        
        mutations = []
        discovered_ids = discovered_ids or []
        
        # Extract IDs from the original request
        request_ids = self._extract_ids_from_request(original_url, body)
        
        if not request_ids:
            logger.debug("No IDs found in request, skipping mutations")
            return mutations
            
        # Generate different types of mutations
        for mutation_type in ['id_swap', 'increment', 'decrement', 'random_id', 'admin_id']:
            type_mutations = self._generate_mutations_by_type(
                original_url, method, headers, body, request_ids,
                identity_ids, discovered_ids, mutation_type
            )
            mutations.extend(type_mutations)
            
        logger.debug(f"Generated {len(mutations)} mutations")
        return mutations
        
    def _extract_ids_from_request(self, url: str, body: Optional[str]) -> Dict[str, str]:
        """
        Extract ID values from request URL and body.
        
        Args:
            url: Request URL
            body: Request body
            
        Returns:
            Dictionary mapping location to ID value
        """
        ids = {}
        
        # Extract from URL path
        parsed = urlparse(url)
        path_segments = parsed.path.split('/')
        
        for i, segment in enumerate(path_segments):
            if segment and self._looks_like_id(segment):
                ids[f'path_{i}'] = segment
                
        # Extract from query parameters
        query_params = parse_qs(parsed.query)
        for param_name, param_values in query_params.items():
            if param_values and self._looks_like_id(param_values[0]):
                ids[f'query_{param_name}'] = param_values[0]
                
        # Extract from body (if JSON)
        if body:
            try:
                import json
                body_data = json.loads(body)
                body_ids = self._extract_ids_from_json(body_data)
                for field_path, id_value in body_ids.items():
                    ids[f'body_{field_path}'] = id_value
            except (json.JSONDecodeError, Exception):
                # Try regex extraction for non-JSON bodies
                body_ids = self.id_miner._mine_text_content(body)
                for i, id_value in enumerate(body_ids):
                    ids[f'body_text_{i}'] = id_value
                    
        return ids
        
    def _extract_ids_from_json(self, data: Any, path: str = '') -> Dict[str, str]:
        """Recursively extract IDs from JSON data."""
        ids = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                if isinstance(value, (str, int)) and self._looks_like_id(str(value)):
                    ids[current_path] = str(value)
                elif isinstance(value, (dict, list)):
                    ids.update(self._extract_ids_from_json(value, current_path))
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                ids.update(self._extract_ids_from_json(item, current_path))
                
        return ids
        
    def _looks_like_id(self, value: str) -> bool:
        """Check if a value looks like an ID."""
        # Use the ID miner's classification
        classified_type = self.id_miner._classify_single_id(value)
        return classified_type != 'unknown'
        
    def _generate_mutations_by_type(self,
                                   original_url: str,
                                   method: str,
                                   headers: Dict[str, str],
                                   body: Optional[str],
                                   request_ids: Dict[str, str],
                                   identity_ids: Dict[str, List[str]],
                                   discovered_ids: List[str],
                                   mutation_type: str) -> List[MutatedRequest]:
        """Generate mutations of a specific type."""
        mutations = []
        
        for id_location, original_id in request_ids.items():
            mutation_values = self._get_mutation_values(
                original_id, identity_ids, discovered_ids, mutation_type
            )
            
            for mutation_value in mutation_values:
                try:
                    mutated_request = self._create_mutated_request(
                        original_url, method, headers, body,
                        id_location, original_id, mutation_value, mutation_type
                    )
                    mutations.append(mutated_request)
                except Exception as e:
                    logger.warning(f"Failed to create mutation: {e}")
                    
        return mutations
        
    def _get_mutation_values(self,
                           original_id: str,
                           identity_ids: Dict[str, List[str]],
                           discovered_ids: List[str],
                           mutation_type: str) -> List[str]:
        """Get mutation values based on mutation type."""
        values = []
        
        if mutation_type == 'id_swap':
            # Swap with IDs from other identities
            for identity_name, ids in identity_ids.items():
                values.extend(ids)
            # Also try discovered IDs
            values.extend(discovered_ids)
            
        elif mutation_type == 'increment':
            if original_id.isdigit():
                original_num = int(original_id)
                values.extend([
                    str(original_num + 1),
                    str(original_num + 10),
                    str(original_num + 100)
                ])
            elif self.id_miner._classify_single_id(original_id) == 'uuid':
                # Generate new UUIDs
                values.extend([str(uuid.uuid4()) for _ in range(3)])
                
        elif mutation_type == 'decrement':
            if original_id.isdigit():
                original_num = int(original_id)
                values.extend([
                    str(max(0, original_num - 1)),
                    str(max(0, original_num - 10)),
                    str(max(0, original_num - 100))
                ])
                
        elif mutation_type == 'random_id':
            id_type = self.id_miner._classify_single_id(original_id)
            if id_type == 'numeric':
                values.extend(['1', '999999', '0'])
            elif id_type == 'uuid':
                values.extend([str(uuid.uuid4()) for _ in range(2)])
            else:
                values.extend(['admin', 'test', 'guest'])
                
        elif mutation_type == 'admin_id':
            # Common admin/privileged IDs
            values.extend(['1', '0', 'admin', 'root', 'administrator'])
            
        # Remove the original ID from mutations
        return [v for v in values if v != original_id]
        
    def _create_mutated_request(self,
                               original_url: str,
                               method: str,
                               headers: Dict[str, str],
                               body: Optional[str],
                               id_location: str,
                               original_id: str,
                               mutation_value: str,
                               mutation_type: str) -> MutatedRequest:
        """Create a mutated request by replacing an ID value."""
        mutated_url = original_url
        mutated_body = body
        mutated_fields = {id_location: (original_id, mutation_value)}
        
        if id_location.startswith('path_'):
            # Mutate URL path
            mutated_url = self._mutate_url_path(original_url, original_id, mutation_value)
            
        elif id_location.startswith('query_'):
            # Mutate query parameter
            param_name = id_location.replace('query_', '')
            mutated_url = self._mutate_query_param(original_url, param_name, mutation_value)
            
        elif id_location.startswith('body_'):
            # Mutate body content
            mutated_body = self._mutate_body(body, id_location, original_id, mutation_value)
            
        return MutatedRequest(
            original_url=original_url,
            mutated_url=mutated_url,
            method=method,
            headers=headers.copy(),
            body=mutated_body,
            params={},
            mutation_type=mutation_type,
            mutated_fields=mutated_fields,
            metadata={
                'original_id': original_id,
                'mutation_value': mutation_value,
                'id_location': id_location
            }
        )
        
    def _mutate_url_path(self, url: str, original_id: str, mutation_value: str) -> str:
        """Mutate an ID in the URL path."""
        return url.replace(original_id, mutation_value, 1)
        
    def _mutate_query_param(self, url: str, param_name: str, mutation_value: str) -> str:
        """Mutate a query parameter value."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params[param_name] = [mutation_value]
        
        new_query = urlencode(query_params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        
    def _mutate_body(self, body: Optional[str], id_location: str, 
                    original_id: str, mutation_value: str) -> Optional[str]:
        """Mutate an ID in the request body."""
        if not body:
            return body
            
        if id_location.startswith('body_text_'):
            # Simple text replacement
            return body.replace(original_id, mutation_value, 1)
            
        # Try JSON mutation
        try:
            import json
            body_data = json.loads(body)
            field_path = id_location.replace('body_', '')
            
            # Navigate to the field and update it
            self._update_json_field(body_data, field_path, mutation_value)
            
            return json.dumps(body_data)
        except (json.JSONDecodeError, Exception):
            # Fall back to simple text replacement
            return body.replace(original_id, mutation_value, 1)
            
    def _update_json_field(self, data: Any, field_path: str, new_value: str):
        """Update a field in JSON data using dot notation path."""
        path_parts = field_path.split('.')
        current = data
        
        # Navigate to the parent of the target field
        for part in path_parts[:-1]:
            if '[' in part and ']' in part:
                # Handle array indices
                field_name, index_str = part.split('[')
                index = int(index_str.rstrip(']'))
                current = current[field_name][index]
            else:
                current = current[part]
                
        # Update the final field
        final_part = path_parts[-1]
        if '[' in final_part and ']' in final_part:
            field_name, index_str = final_part.split('[')
            index = int(index_str.rstrip(']'))
            current[field_name][index] = new_value
        else:
            current[final_part] = new_value
            
    def generate_boundary_mutations(self, 
                                   original_url: str,
                                   method: str,
                                   headers: Dict[str, str],
                                   body: Optional[str]) -> List[MutatedRequest]:
        """
        Generate boundary value mutations (edge cases).
        
        Args:
            original_url: Original request URL
            method: HTTP method
            headers: Request headers
            body: Request body
            
        Returns:
            List of boundary mutation requests
        """
        mutations = []
        request_ids = self._extract_ids_from_request(original_url, body)
        
        boundary_values = [
            '', '0', '-1', '999999999', 'null', 'undefined',
            '../', '..\\', '%2e%2e%2f', '$(id)', '${id}',
            '<script>alert(1)</script>', "'; DROP TABLE users; --"
        ]
        
        for id_location, original_id in request_ids.items():
            for boundary_value in boundary_values:
                try:
                    mutated_request = self._create_mutated_request(
                        original_url, method, headers, body,
                        id_location, original_id, boundary_value, 'boundary'
                    )
                    mutations.append(mutated_request)
                except Exception as e:
                    logger.warning(f"Failed to create boundary mutation: {e}")
                    
        return mutations
        
    def generate_authorization_mutations(self,
                                       original_url: str,
                                       method: str,
                                       headers: Dict[str, str],
                                       body: Optional[str]) -> List[MutatedRequest]:
        """
        Generate mutations that test authorization bypass.
        
        Args:
            original_url: Original request URL
            method: HTTP method
            headers: Request headers
            body: Request body
            
        Returns:
            List of authorization mutation requests
        """
        mutations = []
        
        # Test with no authorization
        no_auth_headers = {k: v for k, v in headers.items() 
                          if k.lower() not in ['authorization', 'cookie']}
        
        mutations.append(MutatedRequest(
            original_url=original_url,
            mutated_url=original_url,
            method=method,
            headers=no_auth_headers,
            body=body,
            params={},
            mutation_type='no_auth',
            mutated_fields={'authorization': ('present', 'removed')},
            metadata={'mutation_description': 'Authorization header removed'}
        ))
        
        # Test with invalid authorization
        if 'authorization' in headers:
            invalid_auth_headers = headers.copy()
            invalid_auth_headers['authorization'] = 'Bearer invalid_token'
            
            mutations.append(MutatedRequest(
                original_url=original_url,
                mutated_url=original_url,
                method=method,
                headers=invalid_auth_headers,
                body=body,
                params={},
                mutation_type='invalid_auth',
                mutated_fields={'authorization': (headers['authorization'], 'Bearer invalid_token')},
                metadata={'mutation_description': 'Invalid authorization token'}
            ))
            
        return mutations
