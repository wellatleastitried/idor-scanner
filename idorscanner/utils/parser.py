"""
Helpers for scraping JS, HTML
"""

import re
import logging
from typing import List, Dict, Set, Optional, Union
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def extract_links_from_html(html_content: str, base_url: str) -> List[str]:
    """
    Extract all links from HTML content.
    
    Args:
        html_content: HTML content to parse
        base_url: Base URL to resolve relative links
        
    Returns:
        List of absolute URLs
    """
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        links = set()
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(base_url, href)
            links.add(absolute_url)
            
        for script in soup.find_all('script', src=True):
            src = script['src']
            absolute_url = urljoin(base_url, src)
            links.add(absolute_url)
            
        for form in soup.find_all('form', action=True):
            action = form['action']
            absolute_url = urljoin(base_url, action)
            links.add(absolute_url)
            
        return list(links)
        
    except Exception as e:
        logger.warning(f"Failed to extract links from HTML: {e}")
        return []


def extract_forms_from_html(html_content: str, base_url: str) -> List[Dict[str, Union[str, List[Dict[str, str]]]]]:
    """
    Extract form information from HTML content.
    
    Args:
        html_content: HTML content to parse
        base_url: Base URL to resolve relative action URLs
        
    Returns:
        List of form dictionaries with action, method, and inputs
    """
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                form_data['inputs'].append(input_data)
                
            forms.append(form_data)
            
        return forms
        
    except Exception as e:
        logger.warning(f"Failed to extract forms from HTML: {e}")
        return []


def extract_ids_from_html(html_content: str) -> Set[str]:
    """
    Extract potential ID values from HTML content.
    
    Args:
        html_content: HTML content to parse
        
    Returns:
        Set of potential ID values
    """
    ids = set()
    
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Extract ID attributes
        for element in soup.find_all(id=True):
            ids.add(element['id'])
            
        # Extract data-* attributes that might contain IDs
        for element in soup.find_all():
            for attr, value in element.attrs.items():
                if attr.startswith('data-') and isinstance(value, str):
                    # Look for numeric or UUID-like patterns
                    if re.match(r'^\d+$', value) or re.match(r'^[a-f0-9-]{36}$', value, re.IGNORECASE):
                        ids.add(value)
                        
        # Extract IDs from text content using regex patterns
        text_content = soup.get_text()
        ids.update(extract_ids_from_text(text_content))
        
    except Exception as e:
        logger.warning(f"Failed to extract IDs from HTML: {e}")
        
    return ids


def extract_ids_from_text(text: str) -> Set[str]:
    """
    Extract potential ID values from text using regex patterns.
    
    Args:
        text: Text content to search
        
    Returns:
        Set of potential ID values
    """
    ids = set()
    
    # UUID pattern
    uuid_pattern = r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
    ids.update(re.findall(uuid_pattern, text, re.IGNORECASE))
    
    # Numeric ID pattern (3+ digits)
    numeric_pattern = r'\b\d{3,}\b'
    ids.update(re.findall(numeric_pattern, text))
    
    # Email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    ids.update(re.findall(email_pattern, text))
    
    # Hash-like patterns (32+ hex characters)
    hash_pattern = r'\b[a-f0-9]{32,}\b'
    ids.update(re.findall(hash_pattern, text, re.IGNORECASE))
    
    return ids


def extract_endpoints_from_js(js_content: str, base_url: str) -> List[str]:
    """
    Extract API endpoints from JavaScript content.
    
    Args:
        js_content: JavaScript content to parse
        base_url: Base URL to resolve relative endpoints
        
    Returns:
        List of potential API endpoints
    """
    endpoints = set()
    
    try:
        # Common API endpoint patterns in JavaScript
        patterns = [
            r'["\'](?:/api/[^"\']*)["\']',
            r'["\'](?:https?://[^"\']*)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'\.put\s*\(\s*["\']([^"\']+)["\']',
            r'\.delete\s*\(\s*["\']([^"\']+)["\']',
            r'ajax\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Clean up the match and resolve relative URLs
                endpoint = match.strip()
                if endpoint.startswith('/'):
                    endpoint = urljoin(base_url, endpoint)
                elif not endpoint.startswith(('http://', 'https://')):
                    continue  # Skip relative paths that don't start with /
                    
                endpoints.add(endpoint)
                
    except Exception as e:
        logger.warning(f"Failed to extract endpoints from JavaScript: {e}")
        
    return list(endpoints)


def extract_parameters_from_url(url: str) -> Dict[str, str]:
    """
    Extract parameters from URL path and query string.
    
    Args:
        url: URL to parse
        
    Returns:
        Dictionary of parameter names and example values
    """
    params = {}
    
    try:
        parsed = urlparse(url)
        
        # Extract path parameters (look for numeric segments)
        path_segments = parsed.path.split('/')
        for i, segment in enumerate(path_segments):
            if segment.isdigit():
                # Assume previous segment is the parameter name
                if i > 0:
                    param_name = path_segments[i-1].rstrip('s')  # Remove plural 's'
                    params[f"{param_name}_id"] = segment
                    
        # TODO: Parse query parameters
        # For now, just note if query string exists
        if parsed.query:
            params['_has_query_params'] = 'true'
            
    except Exception as e:
        logger.warning(f"Failed to extract parameters from URL {url}: {e}")
        
    return params
