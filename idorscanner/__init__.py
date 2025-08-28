"""
IDOR Scanner - Automated testing for Insecure Direct Object Reference vulnerabilities.

This package provides a comprehensive framework for discovering and testing IDOR vulnerabilities
in web applications through automated crawling, ID mining, mutation testing, and response analysis.
"""

__version__ = "1.0.0"
__author__ = "wellatleastitried"

from .config import ScanConfig, load_config, validate_config
from .identities import IdentityManager, SessionCapsule
from .crawler import WebCrawler, EndpointCatalog
from .miner import IDMiner
from .mutator import RequestMutator, MutatedRequest
from .oracle import IDOROracle, Verdict, TestResult
from .graph import ProvenanceGraph, GraphNode
from .evidence import EvidenceStore
from .reporter import ScanReporter

__all__ = [
    'ScanConfig',
    'load_config', 
    'validate_config',
    'IdentityManager',
    'SessionCapsule',
    'WebCrawler',
    'EndpointCatalog',
    'IDMiner',
    'RequestMutator',
    'MutatedRequest',
    'IDOROracle',
    'Verdict',
    'TestResult',
    'ProvenanceGraph',
    'GraphNode',
    'EvidenceStore',
    'ScanReporter'
]