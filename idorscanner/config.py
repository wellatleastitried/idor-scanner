import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PathConfig:
    """Configuration for allowed and denied paths."""
    allow: List[str]
    deny: List[str]


@dataclass
class IdentityConfig:
    """Configuration for an authentication identity."""
    name: str
    auth_type: str
    credentials: Dict[str, Any]


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    requests_per_second: float
    burst: int
    backoff: bool


@dataclass
class OptionsConfig:
    """General scanning options."""
    follow_redirects: bool
    verify_ssl: bool
    max_depth: int
    max_concurrent: int
    timeout_seconds: float


@dataclass
class OutputConfig:
    """Output configuration."""
    results_dir: str
    redact_headers: List[str]
    redact_fields: List[str]


@dataclass
class ScanConfig:
    """Complete scan configuration."""
    program: str
    domains: List[str]
    paths: PathConfig
    identities: List[IdentityConfig]
    rate_limit: RateLimitConfig
    options: OptionsConfig
    output: OutputConfig


def load_config(config_path: str) -> ScanConfig:
    """
    Load configuration from JSON file.
    
    Args:
        config_path: Path to the configuration JSON file
        
    Returns:
        ScanConfig object with parsed configuration
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
        KeyError: If required fields are missing
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
    logger.info(f"Loading configuration from {config_path}")
    
    try:
        with open(config_file, 'r') as f:
            data = json.load(f)
            
        # Validate required top-level fields
        required_fields = ['program', 'domains', 'paths', 'identities', 'rate_limit', 'options', 'output']
        for field in required_fields:
            if field not in data:
                raise KeyError(f"Required field '{field}' missing from configuration")
                
        # Parse paths configuration
        paths_data = data['paths']
        paths = PathConfig(
            allow=paths_data.get('allow', []),
            deny=paths_data.get('deny', [])
        )
        
        # Parse identities configuration
        identities = []
        for identity_data in data['identities']:
            identity = IdentityConfig(
                name=identity_data['name'],
                auth_type=identity_data['auth_type'],
                credentials=identity_data.get('credentials', {})
            )
            identities.append(identity)
            
        # Parse rate limit configuration
        rate_limit_data = data['rate_limit']
        rate_limit = RateLimitConfig(
            requests_per_second=rate_limit_data['requests_per_second'],
            burst=rate_limit_data['burst'],
            backoff=rate_limit_data.get('backoff', True)
        )
        
        # Parse options configuration
        options_data = data['options']
        options = OptionsConfig(
            follow_redirects=options_data.get('follow_redirects', True),
            verify_ssl=options_data.get('verify_ssl', True),
            max_depth=options_data.get('max_depth', 3),
            max_concurrent=options_data.get('max_concurrent', 10),
            timeout_seconds=options_data.get('timeout_seconds', 15.0)
        )
        
        # Parse output configuration
        output_data = data['output']
        output = OutputConfig(
            results_dir=output_data.get('results_dir', 'results/'),
            redact_headers=output_data.get('redact_headers', []),
            redact_fields=output_data.get('redact_fields', [])
        )
        
        config = ScanConfig(
            program=data['program'],
            domains=data['domains'],
            paths=paths,
            identities=identities,
            rate_limit=rate_limit,
            options=options,
            output=output
        )
        
        logger.info(f"Successfully loaded configuration for program: {config.program}")
        logger.info(f"Domains: {', '.join(config.domains)}")
        logger.info(f"Identities: {', '.join([i.name for i in config.identities])}")
        
        return config
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        raise
    except KeyError as e:
        logger.error(f"Configuration validation failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise


def validate_config(config: ScanConfig) -> bool:
    """
    Validate configuration for common issues.
    
    Args:
        config: Configuration to validate
        
    Returns:
        True if configuration is valid
        
    Raises:
        ValueError: If configuration has validation errors
    """
    errors = []
    
    # Validate domains
    if not config.domains:
        errors.append("At least one domain must be specified")
        
    # Validate identities
    if not config.identities:
        errors.append("At least one identity must be specified")
        
    for identity in config.identities:
        if identity.auth_type not in ['none', 'basic', 'bearer', 'cookie']:
            errors.append(f"Invalid auth_type '{identity.auth_type}' for identity '{identity.name}'")
            
        if identity.auth_type == 'basic':
            if 'username' not in identity.credentials or 'password' not in identity.credentials:
                errors.append(f"Basic auth identity '{identity.name}' missing username or password")
                
        elif identity.auth_type == 'bearer':
            if 'token' not in identity.credentials:
                errors.append(f"Bearer auth identity '{identity.name}' missing token")
                
    # Validate rate limits
    if config.rate_limit.requests_per_second <= 0:
        errors.append("requests_per_second must be positive")
        
    if config.rate_limit.burst <= 0:
        errors.append("burst must be positive")
        
    # Validate options
    if config.options.max_depth <= 0:
        errors.append("max_depth must be positive")
        
    if config.options.max_concurrent <= 0:
        errors.append("max_concurrent must be positive")
        
    if config.options.timeout_seconds <= 0:
        errors.append("timeout_seconds must be positive")
        
    if errors:
        error_message = "Configuration validation failed:\n" + "\n".join(f"- {error}" for error in errors)
        logger.error(error_message)
        raise ValueError(error_message)
        
    return True


def is_path_allowed(path: str, config: ScanConfig) -> bool:
    """
    Check if a path is allowed based on configuration.
    
    Args:
        path: URL path to check
        config: Scan configuration
        
    Returns:
        True if path is allowed, False otherwise
    """
    # Check deny list first
    for deny_pattern in config.paths.deny:
        if path.startswith(deny_pattern):
            return False
            
    # Check allow list
    if not config.paths.allow:
        return True  # If no allow list, allow everything not denied
        
    for allow_pattern in config.paths.allow:
        if path.startswith(allow_pattern):
            return True
            
    return False


def is_domain_in_scope(domain: str, config: ScanConfig) -> bool:
    """
    Check if a domain is in scope.
    
    Args:
        domain: Domain to check
        config: Scan configuration
        
    Returns:
        True if domain is in scope, False otherwise
    """
    return domain in config.domains
