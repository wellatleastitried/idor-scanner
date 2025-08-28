import json
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
from dataclasses import dataclass, asdict
import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """Represents a node in the provenance graph."""
    node_id: str
    node_type: str  # 'auth', 'request', 'mutation', 'assertion'
    timestamp: str
    metadata: Dict[str, Any]
    evidence_refs: List[str]  # References to evidence files
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class GraphEdge:
    """Represents an edge in the provenance graph."""
    source: str
    target: str
    edge_type: str  # 'depends_on', 'mutates', 'validates'
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert edge to dictionary for JSON serialization."""
        return asdict(self)


class ProvenanceGraph:
    """Manages the provenance DAG for IDOR testing."""
    
    def __init__(self, scan_id: str):
        """
        Initialize provenance graph.
        
        Args:
            scan_id: Unique identifier for the scan
        """
        self.scan_id = scan_id
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        
        logger.info(f"Provenance graph initialized for scan: {scan_id}")
        
    def add_auth_node(self, 
                     identity_name: str,
                     auth_type: str,
                     evidence_refs: List[str],
                     metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add an authentication node to the graph.
        
        Args:
            identity_name: Name of the identity being authenticated
            auth_type: Type of authentication (basic, bearer, cookie, etc.)
            evidence_refs: References to authentication evidence
            metadata: Additional metadata
            
        Returns:
            Node ID of the created node
        """
        node_id = f"auth_{identity_name}_{datetime.utcnow().timestamp()}"
        
        node = GraphNode(
            node_id=node_id,
            node_type='auth',
            timestamp=datetime.utcnow().isoformat(),
            metadata={
                'identity_name': identity_name,
                'auth_type': auth_type,
                **(metadata or {})
            },
            evidence_refs=evidence_refs
        )
        
        self.nodes[node_id] = node
        self.graph.add_node(node_id, **node.to_dict())
        
        logger.debug(f"Added auth node: {node_id}")
        return node_id
        
    def add_request_node(self,
                        method: str,
                        url: str,
                        identity_name: str,
                        evidence_refs: List[str],
                        metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add a request node to the graph.
        
        Args:
            method: HTTP method
            url: Request URL
            identity_name: Identity used for the request
            evidence_refs: References to request/response evidence
            metadata: Additional metadata
            
        Returns:
            Node ID of the created node
        """
        node_id = f"request_{datetime.utcnow().timestamp()}"
        
        node = GraphNode(
            node_id=node_id,
            node_type='request',
            timestamp=datetime.utcnow().isoformat(),
            metadata={
                'method': method,
                'url': url,
                'identity_name': identity_name,
                **(metadata or {})
            },
            evidence_refs=evidence_refs
        )
        
        self.nodes[node_id] = node
        self.graph.add_node(node_id, **node.to_dict())
        
        logger.debug(f"Added request node: {node_id}")
        return node_id
        
    def add_mutation_node(self,
                         original_request_id: str,
                         mutation_type: str,
                         mutated_values: Dict[str, Any],
                         evidence_refs: List[str],
                         metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add a mutation node to the graph.
        
        Args:
            original_request_id: ID of the original request being mutated
            mutation_type: Type of mutation (id_swap, increment, etc.)
            mutated_values: Values that were mutated
            evidence_refs: References to mutation evidence
            metadata: Additional metadata
            
        Returns:
            Node ID of the created node
        """
        node_id = f"mutation_{datetime.utcnow().timestamp()}"
        
        node = GraphNode(
            node_id=node_id,
            node_type='mutation',
            timestamp=datetime.utcnow().isoformat(),
            metadata={
                'original_request_id': original_request_id,
                'mutation_type': mutation_type,
                'mutated_values': mutated_values,
                **(metadata or {})
            },
            evidence_refs=evidence_refs
        )
        
        self.nodes[node_id] = node
        self.graph.add_node(node_id, **node.to_dict())
        
        # Add dependency edge to original request
        self.add_edge(node_id, original_request_id, 'mutates')
        
        logger.debug(f"Added mutation node: {node_id}")
        return node_id
        
    def add_assertion_node(self,
                          test_request_id: str,
                          baseline_request_id: str,
                          verdict: str,
                          comparison_results: Dict[str, Any],
                          evidence_refs: List[str],
                          metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add an assertion/validation node to the graph.
        
        Args:
            test_request_id: ID of the test request
            baseline_request_id: ID of the baseline request
            verdict: Test verdict (NO_IDOR, POSSIBLE_IDOR, CONFIRMED_IDOR)
            comparison_results: Results of response comparison
            evidence_refs: References to comparison evidence
            metadata: Additional metadata
            
        Returns:
            Node ID of the created node
        """
        node_id = f"assertion_{datetime.utcnow().timestamp()}"
        
        node = GraphNode(
            node_id=node_id,
            node_type='assertion',
            timestamp=datetime.utcnow().isoformat(),
            metadata={
                'test_request_id': test_request_id,
                'baseline_request_id': baseline_request_id,
                'verdict': verdict,
                'comparison_results': comparison_results,
                **(metadata or {})
            },
            evidence_refs=evidence_refs
        )
        
        self.nodes[node_id] = node
        self.graph.add_node(node_id, **node.to_dict())
        
        # Add dependency edges
        self.add_edge(node_id, test_request_id, 'validates')
        self.add_edge(node_id, baseline_request_id, 'validates')
        
        logger.debug(f"Added assertion node: {node_id}")
        return node_id
        
    def add_edge(self,
                source: str,
                target: str,
                edge_type: str,
                metadata: Optional[Dict[str, Any]] = None):
        """
        Add an edge between two nodes.
        
        Args:
            source: Source node ID
            target: Target node ID
            edge_type: Type of edge relationship
            metadata: Additional edge metadata
        """
        edge = GraphEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            metadata=metadata or {}
        )
        
        self.edges.append(edge)
        self.graph.add_edge(source, target, **edge.to_dict())
        
        logger.debug(f"Added edge: {source} -> {target} ({edge_type})")
        
    def get_dependencies(self, node_id: str) -> List[str]:
        """
        Get all dependencies for a node.
        
        Args:
            node_id: Node to find dependencies for
            
        Returns:
            List of node IDs that this node depends on
        """
        return list(self.graph.successors(node_id))
        
    def get_dependents(self, node_id: str) -> List[str]:
        """
        Get all nodes that depend on this node.
        
        Args:
            node_id: Node to find dependents for
            
        Returns:
            List of node IDs that depend on this node
        """
        return list(self.graph.predecessors(node_id))
        
    def get_path_to_finding(self, assertion_node_id: str) -> List[str]:
        """
        Get the complete path from authentication to a finding.
        
        Args:
            assertion_node_id: ID of an assertion node
            
        Returns:
            List of node IDs representing the path to the finding
        """
        # Find all auth nodes
        auth_nodes = [node_id for node_id, node in self.nodes.items() 
                     if node.node_type == 'auth']
        
        paths = []
        for auth_node in auth_nodes:
            try:
                if nx.has_path(self.graph, auth_node, assertion_node_id):
                    path = nx.shortest_path(self.graph, auth_node, assertion_node_id)
                    paths.append(path)
            except nx.NetworkXNoPath:
                continue
                
        # Return the longest path (most detailed)
        return max(paths, key=len) if paths else []
        
    def to_json(self) -> str:
        """
        Serialize the graph to JSON.
        
        Returns:
            JSON string representation of the graph
        """
        graph_data = {
            'scan_id': self.scan_id,
            'created_at': datetime.utcnow().isoformat(),
            'nodes': [node.to_dict() for node in self.nodes.values()],
            'edges': [edge.to_dict() for edge in self.edges],
            'node_count': len(self.nodes),
            'edge_count': len(self.edges)
        }
        
        return json.dumps(graph_data, indent=2)
        
    @classmethod
    def from_json(cls, json_str: str) -> 'ProvenanceGraph':
        """
        Deserialize a graph from JSON.
        
        Args:
            json_str: JSON string representation
            
        Returns:
            ProvenanceGraph instance
        """
        data = json.loads(json_str)
        
        graph = cls(data['scan_id'])
        
        # Recreate nodes
        for node_data in data['nodes']:
            node = GraphNode(**node_data)
            graph.nodes[node.node_id] = node
            graph.graph.add_node(node.node_id, **node.to_dict())
            
        # Recreate edges
        for edge_data in data['edges']:
            edge = GraphEdge(**edge_data)
            graph.edges.append(edge)
            graph.graph.add_edge(edge.source, edge.target, **edge.to_dict())
            
        return graph
        
    def get_findings_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all findings in the graph.
        
        Returns:
            Dictionary summarizing findings and their verdicts
        """
        findings = []
        
        for node_id, node in self.nodes.items():
            if node.node_type == 'assertion':
                verdict = node.metadata.get('verdict', 'UNKNOWN')
                findings.append({
                    'node_id': node_id,
                    'verdict': verdict,
                    'timestamp': node.timestamp,
                    'test_request_id': node.metadata.get('test_request_id'),
                    'baseline_request_id': node.metadata.get('baseline_request_id')
                })
                
        verdict_counts = {}
        for finding in findings:
            verdict = finding['verdict']
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            
        return {
            'total_findings': len(findings),
            'verdict_counts': verdict_counts,
            'findings': findings
        }
