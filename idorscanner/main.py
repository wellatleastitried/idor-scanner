import asyncio
import logging
import sys
import uuid
from pathlib import Path
from typing import Optional

import click
from pythonjsonlogger import jsonlogger

from .config import load_config, validate_config
from .identities import IdentityManager
from .crawler import WebCrawler
from .miner import IDMiner
from .mutator import RequestMutator
from .oracle import IDOROracle
from .graph import ProvenanceGraph
from .evidence import EvidenceStore
from .reporter import ScanReporter

@click.group(help="IDOR Scanner - Automated testing for Insecure Direct Object Reference vulnerabilities")
def app():
    """IDOR Scanner CLI."""
    pass

logger = logging.getLogger(__name__)


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Setup structured logging."""
    loggers = [logging.getLogger(name) for name in ['idorscanner', '__main__']]
    
    formatter = jsonlogger.JsonFormatter(
        fmt='%(asctime)s %(name)s %(levelname)s %(message)s'
    )
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    for logger_instance in loggers:
        logger_instance.setLevel(getattr(logging, log_level.upper()))
        logger_instance.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        for logger_instance in loggers:
            logger_instance.addHandler(file_handler)
class IDORScanner:
    """Main IDOR scanner orchestrator."""
    
    def __init__(self, config_path: str):
        """Initialize scanner with configuration."""
        self.config_path = config_path
        self.config = None
        self.scan_id = str(uuid.uuid4())
        
        self.identity_manager = IdentityManager()
        self.id_miner = IDMiner()
        self.mutator = RequestMutator()
        self.oracle = IDOROracle()
        self.evidence_store = None
        self.reporter = None
        self.graph = None
        
    async def initialize(self):
        """Initialize scanner components."""
        logger.info(f"Initializing IDOR scanner with scan ID: {self.scan_id}")
        
        self.config = load_config(self.config_path)
        validate_config(self.config)
        
        self.evidence_store = EvidenceStore(self.config.output.results_dir)
        self.reporter = ScanReporter(self.evidence_store, self.config.output.results_dir)
        self.graph = ProvenanceGraph(self.scan_id)
        
        await self._setup_sessions()
        
        logger.info("Scanner initialization complete")
        
    async def _setup_sessions(self):
        """Setup authenticated sessions for all identities."""
        logger.info("Setting up authenticated sessions")
        
        for identity_config in self.config.identities:
            try:
                session = await self.identity_manager.create_session(identity_config)
                
                # Add authentication node to graph
                auth_node_id = self.graph.add_auth_node(
                    identity_name=identity_config.name,
                    auth_type=identity_config.auth_type,
                    evidence_refs=[],  # No evidence for auth setup yet
                    metadata={'credentials_provided': bool(identity_config.credentials)}
                )
                
                logger.info(f"Session created for {identity_config.name}")
                
            except Exception as e:
                logger.error(f"Failed to create session for {identity_config.name}: {e}")
                raise
                
    async def scan(self) -> str:
        """Execute complete IDOR scan."""
        logger.info(f"Starting IDOR scan for program: {self.config.program}")
        
        try:
            endpoints = await self._discovery_phase()
            discovered_ids = await self._mining_phase(endpoints)
            mutations = await self._mutation_phase(endpoints, discovered_ids)
            test_results = await self._testing_phase(mutations)
            report_path = await self._reporting_phase(test_results)
            
            logger.info(f"Scan completed successfully. Report: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
        finally:
            await self.identity_manager.close_all_sessions()
            
    async def _discovery_phase(self):
        """Phase 1: Discover endpoints through crawling."""
        logger.info("Phase 1: Endpoint discovery")
        
        crawler = WebCrawler(self.config, self.identity_manager)
        
        # Perform web crawling
        catalog = await crawler.crawl()
        
        # Try API discovery
        for domain in self.config.domains:
            base_url = f"https://{domain}" if not domain.startswith('http') else domain
            await crawler.discover_api_endpoints(base_url)
            
        endpoints = catalog.get_all_endpoints()
        logger.info(f"Discovered {len(endpoints)} endpoints")
        
        return endpoints
        
    async def _mining_phase(self, endpoints):
        """Phase 2: Mine IDs from endpoint responses."""
        logger.info("Phase 2: ID mining from responses")
        
        discovered_ids = []
        
        # Get first available session for mining
        session = None
        for session_capsule in self.identity_manager.sessions.values():
            if session_capsule.session:
                session = session_capsule
                break
                
        if not session:
            logger.warning("No session available for ID mining")
            return discovered_ids
            
        # Mine IDs from a sample of endpoints
        sample_endpoints = endpoints[:min(len(endpoints), 20)]  # Limit for initial version
        
        for endpoint in sample_endpoints:
            try:
                # Make request to endpoint
                response = await session.session.request(
                    method=endpoint.method,
                    url=endpoint.url_template
                )
                
                if response.status_code < 400:
                    # Mine IDs from response
                    content_type = response.headers.get('content-type', '')
                    mined_ids = self.id_miner.mine_response(
                        url=endpoint.url_template,
                        response_text=response.text,
                        response_headers=dict(response.headers),
                        content_type=content_type
                    )
                    
                    # Collect all found IDs
                    for id_type, ids in mined_ids.items():
                        discovered_ids.extend(ids)
                        
                    # Store evidence
                    evidence_refs = self.evidence_store.store_request_response(
                        request=response.request,
                        response=response,
                        metadata={'phase': 'mining', 'endpoint': endpoint.url_template}
                    )
                    
                    # Add request node to graph
                    self.graph.add_request_node(
                        method=endpoint.method,
                        url=endpoint.url_template,
                        identity_name=session.identity_name,
                        evidence_refs=[evidence_refs['request_hash'], evidence_refs['response_hash']],
                        metadata={'mined_ids_count': len(discovered_ids)}
                    )
                    
            except Exception as e:
                logger.warning(f"Failed to mine IDs from {endpoint.url_template}: {e}")
                
        # Remove duplicates
        discovered_ids = list(set(discovered_ids))
        logger.info(f"Mined {len(discovered_ids)} unique IDs")
        
        return discovered_ids
        
    async def _mutation_phase(self, endpoints, discovered_ids):
        """Phase 3: Generate mutations for testing."""
        logger.info("Phase 3: Mutation generation")
        
        mutations = []
        
        # Group IDs by identity for swapping
        identity_ids = {}
        for identity_name in self.identity_manager.sessions.keys():
            identity_ids[identity_name] = discovered_ids[:5]  # Sample for demo
            
        # Generate mutations for each endpoint
        for endpoint in endpoints:
            if endpoint.method.upper() in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
                try:
                    endpoint_mutations = self.mutator.generate_mutations(
                        original_url=endpoint.url_template,
                        method=endpoint.method,
                        headers={},
                        body=None,
                        identity_ids=identity_ids,
                        discovered_ids=discovered_ids
                    )
                    
                    mutations.extend(endpoint_mutations)
                    
                    # Add mutation nodes to graph
                    for mutation in endpoint_mutations:
                        mutation_node_id = self.graph.add_mutation_node(
                            original_request_id=f"request_{endpoint.url_template}",
                            mutation_type=mutation.mutation_type,
                            mutated_values=dict(mutation.mutated_fields),
                            evidence_refs=[],
                            metadata={'endpoint': endpoint.url_template}
                        )
                        
                except Exception as e:
                    logger.warning(f"Failed to generate mutations for {endpoint.url_template}: {e}")
                    
        logger.info(f"Generated {len(mutations)} mutations")
        
        return mutations
        
    async def _testing_phase(self, mutations):
        """Phase 4: Execute IDOR tests."""
        logger.info("Phase 4: IDOR testing")
        
        if len(mutations) == 0:
            logger.warning("No mutations to test")
            return []
            
        # Get baseline and test sessions
        sessions = list(self.identity_manager.sessions.values())
        if len(sessions) < 2:
            logger.warning("Need at least 2 sessions for IDOR testing")
            return []
            
        baseline_session = sessions[0]
        test_session = sessions[1] if len(sessions) > 1 else sessions[0]
        
        # Execute tests with concurrency limit
        max_concurrent = min(self.config.options.max_concurrent, 5)
        test_results = await self.oracle.batch_test_mutations(
            mutations=mutations[:50],  # Limit for initial version
            baseline_session=baseline_session,
            test_session=test_session,
            max_concurrent=max_concurrent
        )
        
        # Add assertion nodes to graph
        for result in test_results:
            self.graph.add_assertion_node(
                test_request_id=f"mutation_{result.mutated_request.mutated_url}",
                baseline_request_id=f"baseline_{result.mutated_request.original_url}",
                verdict=result.verdict.value,
                comparison_results=result.evidence,
                evidence_refs=[],
                metadata={
                    'confidence': result.confidence,
                    'mutation_type': result.mutated_request.mutation_type
                }
            )
            
        logger.info(f"Completed {len(test_results)} IDOR tests")
        
        return test_results
        
    async def _reporting_phase(self, test_results):
        """Phase 5: Generate reports."""
        logger.info("Phase 5: Report generation")
        
        # Collect authentication information for report
        auth_info = {}
        for identity_name, session_capsule in self.identity_manager.sessions.items():
            auth_data = {
                'auth_type': session_capsule.auth_type,
                'has_cookies': len(session_capsule.cookies) > 0,
                'cookie_count': len(session_capsule.cookies),
                'has_auth_headers': len(session_capsule.headers) > 0,
                'auth_header_count': len(session_capsule.headers),
                'auth_headers': list(session_capsule.headers.keys()),  # Header names only, not values
                'cookie_names': list(session_capsule.cookies.keys())   # Cookie names only, not values
            }
            auth_info[identity_name] = auth_data
        
        scan_metadata = {
            'config_file': self.config_path,
            'domains': self.config.domains,
            'identities': [i.name for i in self.config.identities],
            'test_count': len(test_results),
            'authentication_info': auth_info
        }
        
        # Generate comprehensive report
        report_path = self.reporter.generate_report(
            scan_id=self.scan_id,
            program_name=self.config.program,
            test_results=test_results,
            provenance_graph=self.graph,
            scan_metadata=scan_metadata
        )
        
        # Save provenance graph
        graph_file = Path(self.config.output.results_dir) / f"provenance_graph_{self.scan_id}.json"
        with open(graph_file, 'w') as f:
            f.write(self.graph.to_json())
            
        logger.info(f"Provenance graph saved: {graph_file}")
        
        return report_path


@app.command()
@click.argument('scope_file')
@click.option('--log-level', default='INFO', help='Logging level')
@click.option('--log-file', default='/tmp/idor-scanner.log', help='Log file path (default: /tmp/idor-scanner.log)')
def scan(scope_file, log_level, log_file):
    """Execute IDOR vulnerability scan based on scope configuration."""
    
    setup_logging(log_level, log_file)
    
    if not Path(scope_file).exists():
        click.echo(f"Error: Scope file not found: {scope_file}", err=True)
        sys.exit(1)
        
    async def run_scan():
        scanner = IDORScanner(scope_file)
        try:
            await scanner.initialize()
            report_path = await scanner.scan()
            click.echo(f"Scan completed successfully!")
            click.echo(f"Report generated: {report_path}")
        except Exception as e:
            click.echo(f"Scan failed: {e}", err=True)
            sys.exit(1)
            
    # Run the async scan
    try:
        asyncio.run(run_scan())
    except KeyboardInterrupt:
        click.echo("Scan interrupted by user", err=True)
        sys.exit(1)


@app.command()
@click.argument('scope_file')
def validate(scope_file):
    """Validate scope configuration file."""
    
    try:
        config = load_config(scope_file)
        validate_config(config)
        click.echo("✓ Configuration is valid")
        click.echo(f"Program: {config.program}")
        click.echo(f"Domains: {', '.join(config.domains)}")
        click.echo(f"Identities: {', '.join([i.name for i in config.identities])}")
    except Exception as e:
        click.echo(f"✗ Configuration validation failed: {e}", err=True)
        sys.exit(1)


@app.command()
def version():
    """Show version information."""
    click.echo("IDOR Scanner v1.0.0")
    click.echo("Automated IDOR vulnerability testing tool")


if __name__ == "__main__":
    app()
