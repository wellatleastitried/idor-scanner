import asyncio
import logging
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass
from .utils.http import HttpSession
from .utils.diff import diff_json, diff_html
from .mutator import MutatedRequest
from .identities import SessionCapsule

logger = logging.getLogger(__name__)


class Verdict(Enum):
    """IDOR test verdict values."""
    NO_IDOR = "NO_IDOR"
    POSSIBLE_IDOR = "POSSIBLE_IDOR"
    CONFIRMED_IDOR = "CONFIRMED_IDOR"
    ERROR = "ERROR"


@dataclass
class TestResult:
    """Result of an IDOR test execution."""
    mutated_request: MutatedRequest
    baseline_response: Optional[Dict[str, Any]]
    test_response: Optional[Dict[str, Any]]
    verdict: Verdict
    confidence: float  # 0.0 to 1.0
    evidence: Dict[str, Any]
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            'mutated_request': self.mutated_request.to_dict(),
            'baseline_response': self.baseline_response,
            'test_response': self.test_response,
            'verdict': self.verdict.value,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'error_message': self.error_message
        }


class IDOROracle:
    """Executes IDOR tests and determines verdicts through response comparison."""
    
    def __init__(self):
        """Initialize the IDOR oracle."""
        self.baseline_cache: Dict[str, Dict[str, Any]] = {}
        
    async def test_mutation(self,
                           mutated_request: MutatedRequest,
                           baseline_session: SessionCapsule,
                           test_session: SessionCapsule) -> TestResult:
        """
        Test a single mutation for IDOR vulnerability.
        
        Args:
            mutated_request: The mutated request to test
            baseline_session: Session for the legitimate user
            test_session: Session for the attacking user
            
        Returns:
            TestResult with verdict and evidence
        """
        logger.debug(f"Testing mutation: {mutated_request.mutation_type} on {mutated_request.mutated_url}")
        
        try:
            baseline_response = await self._get_baseline_response(
                mutated_request.original_url,
                mutated_request.method,
                mutated_request.headers,
                mutated_request.body,
                baseline_session
            )
            
            test_response = await self._execute_test_request(
                mutated_request,
                test_session
            )
            
            verdict, confidence, evidence = self._analyze_responses(
                baseline_response, test_response, mutated_request
            )
            
            return TestResult(
                mutated_request=mutated_request,
                baseline_response=baseline_response,
                test_response=test_response,
                verdict=verdict,
                confidence=confidence,
                evidence=evidence
            )
            
        except Exception as e:
            logger.error(f"Error testing mutation: {e}")
            return TestResult(
                mutated_request=mutated_request,
                baseline_response=None,
                test_response=None,
                verdict=Verdict.ERROR,
                confidence=0.0,
                evidence={},
                error_message=str(e)
            )
            
    async def _get_baseline_response(self,
                                   url: str,
                                   method: str,
                                   headers: Dict[str, str],
                                   body: Optional[str],
                                   session: SessionCapsule) -> Dict[str, Any]:
        """Get baseline response from legitimate user."""
        cache_key = f"{method}:{url}:{hash(str(sorted(headers.items())))}"
        
        if cache_key in self.baseline_cache:
            logger.debug("Using cached baseline response")
            return self.baseline_cache[cache_key]
            
        logger.debug(f"Getting baseline response for {method} {url}")
        
        response = await session.session.request(
            method=method,
            url=url,
            headers=headers,
            data=body if body else None
        )
        
        response_data = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text,
            'content_length': len(response.content),
            'elapsed_ms': response.elapsed.total_seconds() * 1000
        }
        
        self.baseline_cache[cache_key] = response_data
        
        return response_data
        
    async def _execute_test_request(self,
                                  mutated_request: MutatedRequest,
                                  session: SessionCapsule) -> Dict[str, Any]:
        """Execute the mutated test request."""
        logger.debug(f"Executing test request: {mutated_request.method} {mutated_request.mutated_url}")
        
        response = await session.session.request(
            method=mutated_request.method,
            url=mutated_request.mutated_url,
            headers=mutated_request.headers,
            data=mutated_request.body if mutated_request.body else None
        )
        
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text,
            'content_length': len(response.content),
            'elapsed_ms': response.elapsed.total_seconds() * 1000
        }
        
    def _analyze_responses(self,
                          baseline_response: Dict[str, Any],
                          test_response: Dict[str, Any],
                          mutated_request: MutatedRequest) -> tuple[Verdict, float, Dict[str, Any]]:
        """
        Analyze baseline and test responses to determine IDOR verdict.
        
        Args:
            baseline_response: Legitimate user's response
            test_response: Attacking user's response
            mutated_request: The mutation that was tested
            
        Returns:
            Tuple of (verdict, confidence, evidence)
        """
        evidence = {
            'status_code_baseline': baseline_response['status_code'],
            'status_code_test': test_response['status_code'],
            'content_length_baseline': baseline_response['content_length'],
            'content_length_test': test_response['content_length'],
            'response_time_baseline': baseline_response['elapsed_ms'],
            'response_time_test': test_response['elapsed_ms']
        }
        
        # Status code analysis
        baseline_status = baseline_response['status_code']
        test_status = test_response['status_code']
        
        # If test request fails with 4xx/5xx, likely no IDOR
        if test_status >= 400:
            if baseline_status < 400:
                # Access denied for attacker, allowed for legitimate user
                return Verdict.NO_IDOR, 0.9, {**evidence, 'reason': 'Access denied for attacker'}
            else:
                # Both failed, inconclusive
                return Verdict.NO_IDOR, 0.5, {**evidence, 'reason': 'Both requests failed'}
                
        # If baseline fails but test succeeds, potential privilege escalation
        if baseline_status >= 400 and test_status < 400:
            return Verdict.CONFIRMED_IDOR, 0.8, {**evidence, 'reason': 'Privilege escalation detected'}
            
        # Both requests succeeded, need content analysis
        if baseline_status < 400 and test_status < 400:
            return self._analyze_successful_responses(baseline_response, test_response, evidence)
            
        return Verdict.NO_IDOR, 0.3, {**evidence, 'reason': 'Inconclusive status codes'}
        
    def _analyze_successful_responses(self,
                                    baseline_response: Dict[str, Any],
                                    test_response: Dict[str, Any],
                                    evidence: Dict[str, Any]) -> tuple[Verdict, float, Dict[str, Any]]:
        """Analyze content of successful responses."""
        baseline_content = baseline_response['content']
        test_content = test_response['content']
        
        # Check if responses are identical
        if baseline_content == test_content:
            return Verdict.CONFIRMED_IDOR, 0.95, {
                **evidence, 
                'reason': 'Identical responses - full access granted'
            }
            
        # Analyze content type and perform semantic diff
        baseline_content_type = baseline_response['headers'].get('content-type', '').lower()
        test_content_type = test_response['headers'].get('content-type', '').lower()
        
        if 'json' in baseline_content_type and 'json' in test_content_type:
            return self._analyze_json_responses(baseline_content, test_content, evidence)
        elif 'html' in baseline_content_type and 'html' in test_content_type:
            return self._analyze_html_responses(baseline_content, test_content, evidence)
        else:
            return self._analyze_text_responses(baseline_content, test_content, evidence)
            
    def _analyze_json_responses(self,
                              baseline_content: str,
                              test_content: str,
                              evidence: Dict[str, Any]) -> tuple[Verdict, float, Dict[str, Any]]:
        """Analyze JSON response content for IDOR indicators."""
        try:
            diff_result = diff_json(baseline_content, test_content)
            
            if not diff_result:
                # No differences found
                return Verdict.CONFIRMED_IDOR, 0.95, {
                    **evidence,
                    'reason': 'Identical JSON responses',
                    'content_diff': None
                }
                
            evidence['content_diff'] = diff_result
            
            # Check for ownership markers in the differences
            if self._contains_ownership_markers(diff_result):
                return Verdict.POSSIBLE_IDOR, 0.7, {
                    **evidence,
                    'reason': 'Different ownership markers in responses'
                }
                
            # Check for substantial content similarity
            similarity_score = self._calculate_similarity_score(diff_result)
            if similarity_score > 0.8:
                return Verdict.POSSIBLE_IDOR, similarity_score, {
                    **evidence,
                    'reason': f'High content similarity ({similarity_score:.2f})'
                }
            elif similarity_score > 0.5:
                return Verdict.POSSIBLE_IDOR, similarity_score, {
                    **evidence,
                    'reason': f'Moderate content similarity ({similarity_score:.2f})'
                }
            else:
                return Verdict.NO_IDOR, 0.3, {
                    **evidence,
                    'reason': 'Low content similarity - likely different resources'
                }
                
        except Exception as e:
            logger.warning(f"JSON analysis failed: {e}")
            return Verdict.NO_IDOR, 0.1, {
                **evidence,
                'reason': 'JSON analysis failed',
                'error': str(e)
            }
            
    def _analyze_html_responses(self,
                              baseline_content: str,
                              test_content: str,
                              evidence: Dict[str, Any]) -> tuple[Verdict, float, Dict[str, Any]]:
        """Analyze HTML response content for IDOR indicators."""
        try:
            diff_result = diff_html(baseline_content, test_content)
            
            if not diff_result:
                return Verdict.CONFIRMED_IDOR, 0.95, {
                    **evidence,
                    'reason': 'Identical HTML responses',
                    'content_diff': None
                }
                
            evidence['content_diff'] = diff_result
            
            # Check if the HTML structure is similar but content differs
            if not diff_result.get('has_changes', True):
                return Verdict.CONFIRMED_IDOR, 0.9, {
                    **evidence,
                    'reason': 'Similar HTML structure with minor differences'
                }
                
            # Analyze text length differences
            text_length_diff = diff_result.get('text_length_diff', 0)
            if abs(text_length_diff) < 100:  # Small difference
                return Verdict.POSSIBLE_IDOR, 0.6, {
                    **evidence,
                    'reason': 'Similar HTML content with small differences'
                }
            else:
                return Verdict.NO_IDOR, 0.4, {
                    **evidence,
                    'reason': 'Significantly different HTML content'
                }
                
        except Exception as e:
            logger.warning(f"HTML analysis failed: {e}")
            return Verdict.NO_IDOR, 0.1, {
                **evidence,
                'reason': 'HTML analysis failed',
                'error': str(e)
            }
            
    def _analyze_text_responses(self,
                              baseline_content: str,
                              test_content: str,
                              evidence: Dict[str, Any]) -> tuple[Verdict, float, Dict[str, Any]]:
        """Analyze plain text responses."""
        # Simple text comparison
        if baseline_content == test_content:
            return Verdict.CONFIRMED_IDOR, 0.95, {
                **evidence,
                'reason': 'Identical text responses'
            }
            
        # Calculate similarity based on length and common substrings
        len_baseline = len(baseline_content)
        len_test = len(test_content)
        
        if len_baseline == 0 and len_test == 0:
            return Verdict.CONFIRMED_IDOR, 0.9, {
                **evidence,
                'reason': 'Both responses empty'
            }
            
        length_ratio = min(len_baseline, len_test) / max(len_baseline, len_test, 1)
        
        if length_ratio > 0.9:
            return Verdict.POSSIBLE_IDOR, 0.6, {
                **evidence,
                'reason': 'Similar response lengths'
            }
        else:
            return Verdict.NO_IDOR, 0.4, {
                **evidence,
                'reason': 'Different response lengths'
            }
            
    def _contains_ownership_markers(self, diff_result: Dict[str, Any]) -> bool:
        """Check if differences contain ownership-related markers."""
        ownership_keywords = [
            'user', 'owner', 'created_by', 'author', 'account',
            'tenant', 'organization', 'team', 'group', 'customer'
        ]
        
        diff_str = str(diff_result).lower()
        return any(keyword in diff_str for keyword in ownership_keywords)
        
    def _calculate_similarity_score(self, diff_result: Dict[str, Any]) -> float:
        """Calculate a similarity score from diff results."""
        if not diff_result.get('differences'):
            return 1.0
            
        differences = diff_result['differences']
        
        # Count different types of changes
        change_count = 0
        change_count += len(differences.get('values_changed', {}))
        change_count += len(differences.get('dictionary_item_added', {}))
        change_count += len(differences.get('dictionary_item_removed', {}))
        
        # Simple heuristic: more changes = less similarity
        if change_count == 0:
            return 1.0
        elif change_count <= 2:
            return 0.8
        elif change_count <= 5:
            return 0.6
        elif change_count <= 10:
            return 0.4
        else:
            return 0.2
            
    async def batch_test_mutations(self,
                                 mutations: List[MutatedRequest],
                                 baseline_session: SessionCapsule,
                                 test_session: SessionCapsule,
                                 max_concurrent: int = 5) -> List[TestResult]:
        """
        Test multiple mutations concurrently.
        
        Args:
            mutations: List of mutations to test
            baseline_session: Session for baseline requests
            test_session: Session for test requests
            max_concurrent: Maximum concurrent tests
            
        Returns:
            List of test results
        """
        logger.info(f"Testing {len(mutations)} mutations with max concurrency {max_concurrent}")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def test_with_semaphore(mutation):
            async with semaphore:
                return await self.test_mutation(mutation, baseline_session, test_session)
                
        tasks = [test_with_semaphore(mutation) for mutation in mutations]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and convert to TestResult objects
        test_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Mutation test failed: {result}")
            else:
                test_results.append(result)
                
        return test_results
        
    def get_findings_summary(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """
        Generate a summary of findings from test results.
        
        Args:
            test_results: List of test results
            
        Returns:
            Summary dictionary
        """
        verdict_counts = {verdict.value: 0 for verdict in Verdict}
        high_confidence_findings = []
        
        for result in test_results:
            verdict_counts[result.verdict.value] += 1
            
            if result.verdict in [Verdict.CONFIRMED_IDOR, Verdict.POSSIBLE_IDOR] and result.confidence > 0.7:
                high_confidence_findings.append(result)
                
        return {
            'total_tests': len(test_results),
            'verdict_counts': verdict_counts,
            'high_confidence_findings': len(high_confidence_findings),
            'confirmed_idor_count': verdict_counts[Verdict.CONFIRMED_IDOR.value],
            'possible_idor_count': verdict_counts[Verdict.POSSIBLE_IDOR.value],
            'no_idor_count': verdict_counts[Verdict.NO_IDOR.value],
            'error_count': verdict_counts[Verdict.ERROR.value]
        }
