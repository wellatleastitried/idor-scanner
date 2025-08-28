# IDOR Scanner

A comprehensive tool for detecting Insecure Direct Object Reference (IDOR) vulnerabilities in web applications through automated testing and response analysis.

## Disclaimer

This tool is intended solely for authorized security testing and educational purposes. Users are responsible for ensuring they have explicit permission to test target applications. Unauthorized testing of systems you do not own is illegal and unethical. The authors are not responsible for any misuse of this software.

## Installation

### Prerequisites

- Python 3.12 or higher
- Docker (optional, for containerized deployment)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/wellatleastitried/idor-scanner.git
cd idor-scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Docker Installation

Build the Docker image:
```bash
docker build -t idorscanner .
```

## Usage Instructions

### Basic Scan

```bash
python -m idorscanner scan scope.json
```

### With Custom Logging

```bash
python -m idorscanner scan scope.json --log-level DEBUG --log-file /tmp/my-scan.log
```

### Validate Configuration

```bash
python -m idorscanner validate scope.json
```

### Docker Usage

#### Using the Docker Wrapper Script (Recommended)

For convenience, use the provided `idor-docker.sh` script:

```bash
# Make the script executable (first time only)
chmod +x idor-docker.sh

# Basic scan (results stay in container)
./idor-docker.sh basic

# Scan with results accessible on host
./idor-docker.sh results

# Scan with logs and results accessible on host
./idor-docker.sh logs

# Validate scope configuration
./idor-docker.sh validate
```

#### Manual Docker Commands

If you prefer to run Docker commands directly:

```bash
# Basic scan - just mount your scope file (results stay in container)
docker run -v $(pwd)/scope.json:/app/scope.json idorscanner

# Scan with results accessible on host
docker run -v $(pwd)/scope.json:/app/scope.json -v $(pwd)/results:/app/results idorscanner

# Scan with logs accessible on host  
docker run -v $(pwd)/scope.json:/app/scope.json -v $(pwd)/results:/app/results -v /tmp:/tmp idorscanner

# Override command (e.g., to validate instead of scan)
docker run -v $(pwd)/scope.json:/app/scope.json idorscanner validate /app/scope.json
```

**Note**: The results directory path is configured in your scope.json file under `output.results_dir`. Mount this path as a volume if you want results accessible on your host machine.

### Scope Configuration

Create a scope configuration file to define testing parameters:

```json
{
    "program": "Example Bug Bounty",
    "domains": [
        "app.example.com",
        "api.example.com"
    ],
    "paths": {
        "allow": ["/api/", "/users/", "/orders/"],
        "deny": ["/admin/", "/internal/"]
    },
    "identities": [
        {
            "name": "anon",
            "auth_type": "none"
        },
        {
            "name": "userA",
            "auth_type": "basic",
            "credentials": {
                "username": "userA@example.com",
                "password": "password123"
            }
        },
        {
            "name": "userB",
            "auth_type": "bearer",
            "credentials": {
                "token": "JWT_TOKEN_HERE"
            }
        }
    ],
    "rate_limit": {
        "requests_per_second": 5,
        "burst": 10,
        "backoff": true
    },
    "options": {
        "follow_redirects": true,
        "verify_ssl": true,
        "max_depth": 3,
        "max_concurrent": 10,
        "timeout_seconds": 15
    },
    "output": {
        "results_dir": "results/",
        "redact_headers": ["Authorization", "Cookie"],
        "redact_fields": ["password", "token"]
    }
}
```

### Command Options

#### scan command
- `scope_file`: Path to the scope configuration JSON file (required argument)
- `--log-level`: Logging level (default: INFO)
- `--log-file`: Log file path (default: /tmp/idor-scanner.log)

#### validate command  
- `scope_file`: Path to the scope configuration JSON file to validate (required argument)

**Note**: Target URLs, authentication details, and results directory are all configured in the scope file, not as command-line arguments.

## Workflow and Architecture

### Overview

The IDOR scanner implements a comprehensive testing methodology that combines intelligent crawling, mutation-based testing, and semantic response analysis to identify potential IDOR vulnerabilities.

### Core Components

#### 1. Crawler (`crawler.py`)
Performs intelligent web application discovery using breadth-first traversal with configurable depth limits and scope filtering. The crawler respects robots.txt, implements rate limiting, and extracts endpoints from HTML forms, JavaScript, and API documentation.

#### 2. Identity Manager (`identities.py`)
Manages multiple user sessions and authentication contexts. Supports various authentication methods including bearer tokens, cookies, and custom headers. Each identity maintains its own session state and can be configured with different privilege levels.

#### 3. ID Miner (`miner.py`)
Extracts potential object identifiers from HTTP responses using multiple techniques:
- URL path parameter analysis with regex pattern matching
- JSON field extraction for nested object structures
- HTML attribute mining for form inputs and data attributes
- Header value parsing for correlation IDs and references
- Text content analysis using configurable patterns

#### 4. Mutation Engine (`mutator.py`)
Generates test cases by systematically mutating discovered identifiers:
- Numeric ID manipulation (increment/decrement, boundary values)
- UUID/GUID variation using discovered patterns
- String-based ID fuzzing with common variations
- Context-aware mutations based on response correlation

#### 5. Oracle System (`oracle.py`)
Implements sophisticated response analysis to determine IDOR vulnerability status:
- HTTP status code comparison between legitimate and unauthorized requests
- Semantic content diffing for JSON and HTML responses
- Ownership marker detection to identify data leakage
- Confidence scoring based on response similarity metrics

#### 6. Evidence Collection (`evidence.py`)
Maintains comprehensive audit trails including:
- Complete HTTP request/response pairs for all test cases
- Provenance graphs tracking the relationship between discoveries and tests
- Structured JSON logging for automated analysis
- File-based evidence storage with unique scan identifiers

#### 7. Provenance Graph (`graph.py`)
Builds a directed acyclic graph (DAG) representing the testing workflow:
- Nodes represent actions (authentication, requests, mutations, assertions)
- Edges represent dependencies and data flow
- Enables complete audit trails and result reproducibility
- Supports JSON serialization for persistence and analysis

### Testing Methodology

#### Phase 1: Discovery and Mapping
1. **Crawling**: Systematically discover application endpoints within defined scope
2. **Authentication**: Establish sessions for both legitimate and attacking users
3. **Response Collection**: Gather baseline responses for all discovered endpoints

#### Phase 2: ID Mining and Analysis
1. **Pattern Extraction**: Identify potential object references using multiple extraction techniques
2. **Correlation Analysis**: Establish relationships between IDs found across different responses
3. **Type Classification**: Categorize identifiers by type (numeric, UUID, slug) for targeted mutations

#### Phase 3: Mutation and Testing
1. **Test Case Generation**: Create systematic mutations of discovered identifiers
2. **Request Execution**: Perform requests using attacking user context with mutated IDs
3. **Response Capture**: Collect complete HTTP exchanges for analysis

#### Phase 4: Vulnerability Assessment
1. **Response Comparison**: Analyze differences between legitimate and unauthorized responses
2. **Semantic Analysis**: Perform content-aware diffing to detect data exposure
3. **Verdict Assignment**: Classify findings as NO_IDOR, POSSIBLE_IDOR, or CONFIRMED_IDOR
4. **Evidence Generation**: Create comprehensive documentation of identified vulnerabilities

### Design Rationale

#### Modular Architecture
The component-based design enables independent testing and modification of each subsystem. This separation of concerns allows for easy extension of mining techniques, mutation strategies, and analysis methods.

#### Provenance Tracking
Complete audit trails ensure reproducibility and enable detailed forensic analysis of discovered vulnerabilities. The graph-based approach provides clear visibility into the testing methodology and evidence chain.

#### Configurable Scope Management
Flexible scope definition prevents unauthorized testing while enabling comprehensive coverage of legitimate targets. Rate limiting and depth controls ensure responsible testing practices.

#### Multi-Stage Analysis
The oracle system implements multiple analysis techniques to minimize false positives while maintaining high sensitivity to actual vulnerabilities. Confidence scoring provides nuanced assessment of findings.

#### Evidence-First Approach
All testing activities generate structured evidence that can be independently verified. This approach supports both automated analysis and manual review of identified issues.

### Output and Reporting

The scanner generates multiple output formats:
- **JSON Reports**: Structured data suitable for integration with security tools
- **Evidence Files**: Complete HTTP exchanges and analysis metadata
- **Provenance Graphs**: Visual representation of testing workflow
- **Structured Logs**: Detailed execution traces for debugging and audit purposes

All outputs include unique scan identifiers and timestamps to support result correlation and historical analysis.
