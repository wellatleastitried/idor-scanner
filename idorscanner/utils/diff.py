"""
Semantic diffing for JSON/HTML
"""

import json
import logging
from typing import Dict, Any, Optional, Union
from deepdiff import DeepDiff
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def diff_json(original: Union[str, Dict[Any, Any]], 
              modified: Union[str, Dict[Any, Any]]) -> Optional[Dict[str, Any]]:
    """
    Compare two JSON objects and return semantic differences.
    
    Args:
        original: Original JSON data (string or dict)
        modified: Modified JSON data (string or dict)
        
    Returns:
        Dictionary containing the differences, or None if identical
    """
    try:
        if isinstance(original, str):
            original = json.loads(original)
        if isinstance(modified, str):
            modified = json.loads(modified)
            
        diff = DeepDiff(original, modified, ignore_order=True)
        
        if not diff:
            return None
            
        return {
            'type': 'json',
            'differences': dict(diff),
            'has_changes': True,
            'summary': _summarize_json_diff(diff)
        }
        
    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Failed to diff JSON: {e}")
        return {
            'type': 'json',
            'error': str(e),
            'has_changes': True,
            'summary': 'JSON parsing error during diff'
        }


def diff_html(original: str, modified: str) -> Optional[Dict[str, Any]]:
    """
    Compare two HTML documents and return semantic differences.
    
    Args:
        original: Original HTML content
        modified: Modified HTML content
        
    Returns:
        Dictionary containing the differences, or None if identical
    """
    try:
        soup1 = BeautifulSoup(original, 'lxml')
        soup2 = BeautifulSoup(modified, 'lxml')
        
        text1 = soup1.get_text(strip=True)
        text2 = soup2.get_text(strip=True)
        
        if text1 == text2:
            return None
            
        elements1 = _extract_html_elements(soup1)
        elements2 = _extract_html_elements(soup2)
        
        diff = DeepDiff(elements1, elements2, ignore_order=True)
        
        return {
            'type': 'html',
            'differences': dict(diff) if diff else {},
            'has_changes': text1 != text2,
            'text_length_diff': len(text2) - len(text1),
            'summary': _summarize_html_diff(soup1, soup2)
        }
        
    except Exception as e:
        logger.warning(f"Failed to diff HTML: {e}")
        return {
            'type': 'html',
            'error': str(e),
            'has_changes': True,
            'summary': 'HTML parsing error during diff'
        }


def _extract_html_elements(soup: BeautifulSoup) -> Dict[str, Any]:
    """Extract key structural elements from HTML for comparison."""
    return {
        'title': soup.title.string if soup.title else None,
        'forms': len(soup.find_all('form')),
        'links': len(soup.find_all('a')),
        'inputs': len(soup.find_all('input')),
        'tables': len(soup.find_all('table')),
        'headings': [h.get_text(strip=True) for h in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])],
        'text_length': len(soup.get_text(strip=True))
    }


def _summarize_json_diff(diff: DeepDiff) -> str:
    """Create a human-readable summary of JSON differences."""
    changes = []
    
    if 'values_changed' in diff:
        changes.append(f"{len(diff['values_changed'])} values changed")
    if 'dictionary_item_added' in diff:
        changes.append(f"{len(diff['dictionary_item_added'])} items added")
    if 'dictionary_item_removed' in diff:
        changes.append(f"{len(diff['dictionary_item_removed'])} items removed")
    if 'iterable_item_added' in diff:
        changes.append("list items added")
    if 'iterable_item_removed' in diff:
        changes.append("list items removed")
        
    return '; '.join(changes) if changes else 'structural changes detected'


def _summarize_html_diff(soup1: BeautifulSoup, soup2: BeautifulSoup) -> str:
    """Create a human-readable summary of HTML differences."""
    text1_len = len(soup1.get_text(strip=True))
    text2_len = len(soup2.get_text(strip=True))
    
    if text1_len == text2_len:
        return "content changed (same length)"
    elif text2_len > text1_len:
        return f"content expanded by {text2_len - text1_len} characters"
    else:
        return f"content reduced by {text1_len - text2_len} characters"
