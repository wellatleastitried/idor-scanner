import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from .oracle import TestResult, Verdict
from .graph import ProvenanceGraph
from .evidence import EvidenceStore

logger = logging.getLogger(__name__)


class ScanReporter:
    """Generates comprehensive scan reports with findings and evidence."""
    
    def __init__(self, evidence_store: EvidenceStore, output_dir: str):
        """
        Initialize scan reporter.
        
        Args:
            evidence_store: Evidence store for linking artifacts
            output_dir: Directory for output files
        """
        self.evidence_store = evidence_store
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_report(self,
                       scan_id: str,
                       program_name: str,
                       test_results: List[TestResult],
                       provenance_graph: ProvenanceGraph,
                       scan_metadata: Dict[str, Any]) -> str:
        """
        Generate a comprehensive scan report.
        
        Args:
            scan_id: Unique scan identifier
            program_name: Name of the bug bounty program
            test_results: List of IDOR test results
            provenance_graph: Provenance graph for the scan
            scan_metadata: Additional scan metadata
            
        Returns:
            Path to the generated report file
        """
        logger.info(f"Generating scan report for {scan_id}")
        
        # Analyze findings
        findings = self._analyze_findings(test_results)
        executive_summary = self._generate_executive_summary(findings, program_name)
        technical_details = self._generate_technical_details(test_results, provenance_graph)
        evidence_refs = self._collect_evidence_references(test_results)
        
        report = {
            'scan_metadata': {
                'scan_id': scan_id,
                'program_name': program_name,
                'generated_at': datetime.utcnow().isoformat(),
                'scanner_version': '1.0.0',
                **scan_metadata
            },
            'executive_summary': executive_summary,
            'findings': findings,
            'technical_details': technical_details,
            'evidence_references': evidence_refs,
            'provenance_graph_summary': provenance_graph.get_findings_summary(),
            'recommendations': self._generate_recommendations(findings)
        }
        
        report_file = self.output_dir / f"scan_report_{scan_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        summary_file = self.output_dir / f"scan_summary_{scan_id}.md"
        self._generate_markdown_summary(report, summary_file)
        
        logger.info(f"Report generated: {report_file}")
        return str(report_file)
        
    def _analyze_findings(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Analyze test results to extract key findings."""
        findings = {
            'total_tests': len(test_results),
            'confirmed_vulnerabilities': [],
            'possible_vulnerabilities': [],
            'no_vulnerabilities': [],
            'errors': [],
            'summary_stats': {
                'confirmed_count': 0,
                'possible_count': 0,
                'no_vuln_count': 0,
                'error_count': 0
            },
            'severity_assessment': 'LOW',
            'risk_score': 0.0
        }
        
        for result in test_results:
            finding_entry = {
                'url': result.mutated_request.mutated_url,
                'method': result.mutated_request.method,
                'mutation_type': result.mutated_request.mutation_type,
                'confidence': result.confidence,
                'evidence': result.evidence,
                'test_description': self._describe_test(result.mutated_request),
                'impact_description': self._describe_impact(result)
            }
            
            if result.verdict == Verdict.CONFIRMED_IDOR:
                findings['confirmed_vulnerabilities'].append(finding_entry)
                findings['summary_stats']['confirmed_count'] += 1
            elif result.verdict == Verdict.POSSIBLE_IDOR:
                findings['possible_vulnerabilities'].append(finding_entry)
                findings['summary_stats']['possible_count'] += 1
            elif result.verdict == Verdict.NO_IDOR:
                findings['no_vulnerabilities'].append(finding_entry)
                findings['summary_stats']['no_vuln_count'] += 1
            else:  # ERROR
                findings['errors'].append({
                    **finding_entry,
                    'error_message': result.error_message
                })
                findings['summary_stats']['error_count'] += 1
        
        findings['severity_assessment'] = self._assess_severity(findings)
        findings['risk_score'] = self._calculate_risk_score(findings)
        
        return findings
        
    def _generate_executive_summary(self, findings: Dict[str, Any], program_name: str) -> Dict[str, Any]:
        """Generate executive summary for non-technical stakeholders."""
        confirmed_count = findings['summary_stats']['confirmed_count']
        possible_count = findings['summary_stats']['possible_count']
        total_tests = findings['total_tests']
        
        if confirmed_count > 0:
            risk_level = "HIGH"
            description = (
                f"The security scan of {program_name} identified {confirmed_count} confirmed "
                f"Insecure Direct Object Reference (IDOR) vulnerabilities. These vulnerabilities "
                f"allow unauthorized users to access data or resources belonging to other users."
            )
        elif possible_count > 0:
            risk_level = "MEDIUM"
            description = (
                f"The security scan of {program_name} identified {possible_count} potential "
                f"IDOR vulnerabilities that require manual verification. These issues may allow "
                f"unauthorized access to user data."
            )
        else:
            risk_level = "LOW"
            description = (
                f"The security scan of {program_name} completed {total_tests} tests and found "
                f"no confirmed IDOR vulnerabilities in the tested endpoints."
            )
            
        return {
            'risk_level': risk_level,
            'description': description,
            'key_findings': self._extract_key_findings(findings),
            'business_impact': self._describe_business_impact(findings),
            'recommended_actions': self._get_immediate_actions(findings)
        }
        
    def _generate_technical_details(self, 
                                   test_results: List[TestResult],
                                   provenance_graph: ProvenanceGraph) -> Dict[str, Any]:
        """Generate technical details for security teams."""
        return {
            'methodology': {
                'description': 'IDOR vulnerability testing using automated mutation and response analysis',
                'test_types': [
                    'ID parameter swapping between users',
                    'Numeric ID increment/decrement',
                    'UUID and hash mutation',
                    'Authorization bypass attempts',
                    'Boundary value testing'
                ],
                'analysis_methods': [
                    'HTTP status code comparison',
                    'JSON semantic diff analysis',
                    'HTML content comparison',
                    'Response time analysis'
                ]
            },
            'test_coverage': self._calculate_test_coverage(test_results),
            'false_positive_indicators': self._identify_false_positives(test_results),
            'graph_statistics': {
                'total_nodes': len(provenance_graph.nodes),
                'total_edges': len(provenance_graph.edges),
                'auth_nodes': len([n for n in provenance_graph.nodes.values() if n.node_type == 'auth']),
                'request_nodes': len([n for n in provenance_graph.nodes.values() if n.node_type == 'request']),
                'mutation_nodes': len([n for n in provenance_graph.nodes.values() if n.node_type == 'mutation']),
                'assertion_nodes': len([n for n in provenance_graph.nodes.values() if n.node_type == 'assertion'])
            }
        }
        
    def _collect_evidence_references(self, test_results: List[TestResult]) -> List[Dict[str, Any]]:
        """Collect references to evidence artifacts."""
        evidence_refs = []
        
        for result in test_results:
            if result.verdict in [Verdict.CONFIRMED_IDOR, Verdict.POSSIBLE_IDOR]:
                evidence_refs.append({
                    'test_id': f"{result.mutated_request.method}_{hash(result.mutated_request.mutated_url)}",
                    'vulnerability_type': result.verdict.value,
                    'confidence': result.confidence,
                    'artifacts': {
                        'baseline_request': self._format_request_reference(result.baseline_response),
                        'test_request': self._format_request_reference(result.test_response),
                        'curl_command': self._generate_curl_reference(result.mutated_request),
                        'diff_analysis': result.evidence.get('content_diff')
                    },
                    'reproduction_steps': self._generate_reproduction_steps(result)
                })
                
        return evidence_refs
        
    def _describe_test(self, mutated_request) -> str:
        """Generate human-readable test description."""
        descriptions = {
            'id_swap': f"Attempted to access resource by substituting user ID with another user's ID",
            'increment': f"Attempted to access resource by incrementing the ID parameter",
            'decrement': f"Attempted to access resource by decrementing the ID parameter",
            'random_id': f"Attempted to access resource using randomly generated ID values",
            'admin_id': f"Attempted to access resource using common administrative ID values",
            'boundary': f"Attempted to access resource using boundary/edge case ID values",
            'no_auth': f"Attempted to access resource without authentication credentials",
            'invalid_auth': f"Attempted to access resource with invalid authentication"
        }
        
        return descriptions.get(mutated_request.mutation_type, 
                               f"Performed {mutated_request.mutation_type} mutation test")
        
    def _describe_impact(self, result: TestResult) -> str:
        """Describe the potential impact of a finding."""
        if result.verdict == Verdict.CONFIRMED_IDOR:
            return (
                "This vulnerability allows an attacker to access or modify data belonging to other users. "
                "This could lead to unauthorized data disclosure, data tampering, or privacy violations."
            )
        elif result.verdict == Verdict.POSSIBLE_IDOR:
            return (
                "This potential vulnerability may allow unauthorized access to user data. "
                "Manual verification is required to confirm the security impact."
            )
        else:
            return "No security impact identified."
            
    def _assess_severity(self, findings: Dict[str, Any]) -> str:
        """Assess overall severity based on findings."""
        confirmed = findings['summary_stats']['confirmed_count']
        possible = findings['summary_stats']['possible_count']
        
        if confirmed >= 3:
            return 'CRITICAL'
        elif confirmed >= 1:
            return 'HIGH'
        elif possible >= 3:
            return 'MEDIUM'
        elif possible >= 1:
            return 'LOW'
        else:
            return 'INFORMATIONAL'
            
    def _calculate_risk_score(self, findings: Dict[str, Any]) -> float:
        """Calculate numerical risk score (0-10)."""
        confirmed = findings['summary_stats']['confirmed_count']
        possible = findings['summary_stats']['possible_count']
        
        # Base score from confirmed findings
        score = min(confirmed * 3.0, 8.0)
        
        # Add partial score from possible findings
        score += min(possible * 0.5, 2.0)
        
        return min(score, 10.0)
        
    def _extract_key_findings(self, findings: Dict[str, Any]) -> List[str]:
        """Extract key findings for executive summary."""
        key_findings = []
        
        confirmed = findings['confirmed_vulnerabilities']
        possible = findings['possible_vulnerabilities']
        
        if confirmed:
            key_findings.append(f"{len(confirmed)} confirmed IDOR vulnerabilities found")
            
        if possible:
            key_findings.append(f"{len(possible)} potential IDOR vulnerabilities require verification")
            
        if not confirmed and not possible:
            key_findings.append("No IDOR vulnerabilities detected in tested endpoints")
            
        return key_findings
        
    def _describe_business_impact(self, findings: Dict[str, Any]) -> str:
        """Describe business impact of findings."""
        confirmed = findings['summary_stats']['confirmed_count']
        
        if confirmed > 0:
            return (
                "These vulnerabilities pose a significant risk to user privacy and data security. "
                "Attackers could potentially access sensitive user information, leading to "
                "regulatory compliance issues, loss of customer trust, and potential legal liability."
            )
        else:
            return (
                "The current security posture appears adequate for IDOR vulnerabilities in the "
                "tested areas. Continued security testing is recommended as the application evolves."
            )
            
    def _get_immediate_actions(self, findings: Dict[str, Any]) -> List[str]:
        """Get recommended immediate actions."""
        confirmed = findings['summary_stats']['confirmed_count']
        possible = findings['summary_stats']['possible_count']
        
        actions = []
        
        if confirmed > 0:
            actions.extend([
                "Immediately review and fix confirmed IDOR vulnerabilities",
                "Implement proper access controls and authorization checks",
                "Conduct code review of affected endpoints"
            ])
            
        if possible > 0:
            actions.append("Manually verify potential IDOR vulnerabilities")
            
        actions.extend([
            "Implement comprehensive access control testing in CI/CD pipeline",
            "Review application authorization architecture",
            "Consider implementing centralized authorization middleware"
        ])
        
        return actions
        
    def _generate_recommendations(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed recommendations."""
        return {
            'immediate': self._get_immediate_actions(findings),
            'short_term': [
                "Implement automated IDOR testing in development workflow",
                "Establish secure coding guidelines for authorization",
                "Train development team on IDOR prevention techniques"
            ],
            'long_term': [
                "Implement attribute-based access control (ABAC)",
                "Regular security architecture reviews",
                "Continuous security monitoring and testing"
            ],
            'prevention_techniques': [
                "Use indirect object references (e.g., session-based mapping)",
                "Implement proper authorization checks at every access point",
                "Validate user permissions for each requested resource",
                "Use UUIDs instead of sequential numeric IDs where possible",
                "Implement rate limiting and anomaly detection"
            ]
        }
        
    def _calculate_test_coverage(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Calculate test coverage statistics."""
        mutation_types = set()
        endpoints_tested = set()
        
        for result in test_results:
            mutation_types.add(result.mutated_request.mutation_type)
            endpoints_tested.add(f"{result.mutated_request.method} {result.mutated_request.original_url}")
            
        return {
            'unique_endpoints_tested': len(endpoints_tested),
            'mutation_types_used': list(mutation_types),
            'total_test_cases': len(test_results)
        }
        
    def _identify_false_positives(self, test_results: List[TestResult]) -> List[str]:
        """Identify potential false positive indicators."""
        indicators = []
        
        # Look for patterns that might indicate false positives
        for result in test_results:
            if result.verdict == Verdict.CONFIRMED_IDOR and result.confidence < 0.8:
                indicators.append(
                    f"Low confidence ({result.confidence:.2f}) on confirmed finding at "
                    f"{result.mutated_request.mutated_url}"
                )
                
        return indicators
        
    def _format_request_reference(self, response_data: Optional[Dict[str, Any]]) -> Optional[str]:
        """Format a reference to request/response evidence."""
        if not response_data:
            return None
            
        return f"Status: {response_data.get('status_code')}, Length: {response_data.get('content_length')} bytes"
        
    def _generate_curl_reference(self, mutated_request) -> str:
        """Generate a curl command reference for reproduction."""
        # This would typically reference the evidence store
        return f"curl -X {mutated_request.method} '{mutated_request.mutated_url}'"
        
    def _generate_reproduction_steps(self, result: TestResult) -> List[str]:
        """Generate step-by-step reproduction instructions."""
        steps = [
            f"1. Authenticate as a legitimate user and access: {result.mutated_request.original_url}",
            f"2. Note the expected response (baseline)",
            f"3. Authenticate as a different user or no user",
            f"4. Access the mutated URL: {result.mutated_request.mutated_url}",
            f"5. Compare responses - if similar data is returned, IDOR vulnerability is confirmed"
        ]
        
        return steps
        
    def _generate_markdown_summary(self, report: Dict[str, Any], output_file: Path):
        """Generate a human-readable markdown summary."""
        summary = f"""# IDOR Scan Report

## Executive Summary
**Risk Level:** {report['executive_summary']['risk_level']}

{report['executive_summary']['description']}

## Key Findings
"""
        
        for finding in report['executive_summary']['key_findings']:
            summary += f"- {finding}\n"
            
        summary += f"""
## Statistics
- Total Tests: {report['findings']['total_tests']}
- Confirmed Vulnerabilities: {report['findings']['summary_stats']['confirmed_count']}
- Possible Vulnerabilities: {report['findings']['summary_stats']['possible_count']}
- Risk Score: {report['findings']['risk_score']:.1f}/10

## Authentication Analysis
"""
        
        # Add authentication information if available
        auth_info = report['scan_metadata'].get('authentication_info', {})
        if auth_info:
            for identity_name, auth_data in auth_info.items():
                summary += f"**{identity_name}:**\n"
                summary += f"- Authentication Type: {auth_data['auth_type']}\n"
                if auth_data['has_cookies']:
                    summary += f"- Cookies: {auth_data['cookie_count']} found\n"
                if auth_data['has_auth_headers']:
                    summary += f"- Auth Headers: {', '.join(auth_data['auth_headers'])}\n"
                summary += "\n"
        else:
            summary += "No authentication mechanisms detected.\n\n"
            
        summary += f"""
## Business Impact
{report['executive_summary']['business_impact']}

## Immediate Actions Required
"""
        
        for action in report['executive_summary']['recommended_actions']:
            summary += f"- {action}\n"
            
        summary += "\n## Technical Details\nSee full JSON report for detailed technical information.\n"
        
        with open(output_file, 'w') as f:
            f.write(summary)
            
        logger.info(f"Markdown summary generated: {output_file}")
        
    def generate_ai_friendly_summary(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an AI-friendly summary for further processing.
        
        Args:
            report_data: Full report data
            
        Returns:
            Condensed summary optimized for AI analysis
        """
        return {
            'scan_id': report_data['scan_metadata']['scan_id'],
            'findings_summary': {
                'confirmed_count': report_data['findings']['summary_stats']['confirmed_count'],
                'possible_count': report_data['findings']['summary_stats']['possible_count'],
                'severity': report_data['findings']['severity_assessment'],
                'risk_score': report_data['findings']['risk_score']
            },
            'vulnerable_endpoints': [
                {
                    'url': vuln['url'],
                    'method': vuln['method'],
                    'confidence': vuln['confidence'],
                    'description': vuln['test_description']
                }
                for vuln in report_data['findings']['confirmed_vulnerabilities']
            ],
            'key_recommendations': report_data['recommendations']['immediate'][:3],
            'evidence_count': len(report_data['evidence_references'])
        }
