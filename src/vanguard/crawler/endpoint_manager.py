"""
Endpoint Manager - URL deduplication and parameter extraction.

This module sits between crawlers and scanners, managing the discovered
endpoints to ensure efficient scanning without redundancy.

Features:
1. URL normalization and deduplication
2. Parameter extraction and analysis
3. Scope filtering
4. Priority scoring

Reference: @docs/ai-context/architecture.md:66-69
"""

from typing import List, Set, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
import hashlib
from collections import defaultdict

import structlog

# Import Endpoint from crawler module
from .playwright_crawler import Endpoint


@dataclass
class EndpointStats:
    """Statistics for endpoint management"""
    total_discovered: int = 0
    unique_endpoints: int = 0
    duplicate_count: int = 0
    filtered_out_of_scope: int = 0
    by_source: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_method: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


class EndpointManager:
    """
    Manages discovered endpoints with deduplication and prioritization.

    This class ensures that:
    1. No duplicate URLs are scanned
    2. URLs are normalized (same params in different order = same URL)
    3. Out-of-scope URLs are filtered
    4. Endpoints are prioritized by potential attack surface

    Example:
        >>> manager = EndpointManager(allowed_domains=["example.com"])
        >>> manager.add_endpoint(endpoint)
        >>> unique_endpoints = manager.get_unique_endpoints()
        >>> high_priority = manager.get_by_priority(top=10)
    """

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        exclude_extensions: Optional[List[str]] = None,
    ):
        """
        Initialize endpoint manager.

        Args:
            allowed_domains: List of allowed domains for scope filtering
            exclude_extensions: File extensions to exclude (e.g., ['.jpg', '.png'])
        """
        self.allowed_domains = allowed_domains or []
        self.exclude_extensions = exclude_extensions or [
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
            '.pdf', '.zip', '.tar', '.gz',
        ]

        # Endpoint storage
        self._endpoints: Dict[str, Endpoint] = {}  # signature -> Endpoint
        self._url_to_signatures: Dict[str, Set[str]] = defaultdict(set)

        # Statistics
        self.stats = EndpointStats()

        # Logging
        self.logger = structlog.get_logger(__name__)

    def add_endpoint(self, endpoint: Endpoint) -> bool:
        """
        Add an endpoint with deduplication.

        Args:
            endpoint: Endpoint object to add

        Returns:
            True if added (new), False if duplicate
        """
        self.stats.total_discovered += 1
        self.stats.by_source[endpoint.source] += 1
        self.stats.by_method[endpoint.method] += 1

        # Check scope
        if not self._is_in_scope(endpoint.url):
            self.stats.filtered_out_of_scope += 1
            self.logger.debug("endpoint_out_of_scope", url=endpoint.url)
            return False

        # Check extension
        if self._has_excluded_extension(endpoint.url):
            self.logger.debug("endpoint_excluded_extension", url=endpoint.url)
            return False

        # Generate signature for deduplication
        signature = self._generate_signature(endpoint)

        # Check if already exists
        if signature in self._endpoints:
            self.stats.duplicate_count += 1
            self.logger.debug("endpoint_duplicate", url=endpoint.url)
            return False

        # Add new endpoint
        self._endpoints[signature] = endpoint
        self._url_to_signatures[endpoint.url].add(signature)
        self.stats.unique_endpoints += 1

        self.logger.debug(
            "endpoint_added",
            url=endpoint.url,
            method=endpoint.method,
            params=len(endpoint.parameters),
            source=endpoint.source
        )

        return True

    def add_endpoints(self, endpoints: List[Endpoint]) -> int:
        """
        Add multiple endpoints in batch.

        Args:
            endpoints: List of Endpoint objects

        Returns:
            Number of unique endpoints added
        """
        added_count = 0
        for endpoint in endpoints:
            if self.add_endpoint(endpoint):
                added_count += 1

        self.logger.info(
            "endpoints_batch_added",
            total=len(endpoints),
            unique=added_count,
            duplicates=len(endpoints) - added_count
        )

        return added_count

    def get_unique_endpoints(self) -> List[Endpoint]:
        """
        Get all unique endpoints.

        Returns:
            List of unique Endpoint objects
        """
        return list(self._endpoints.values())

    def get_by_priority(self, top: Optional[int] = None) -> List[Endpoint]:
        """
        Get endpoints sorted by priority.

        Priority is based on:
        1. Number of parameters (more params = more attack surface)
        2. HTTP method (POST > GET)
        3. Source (network intercept > crawler > static)

        Args:
            top: Return only top N endpoints (None = all)

        Returns:
            Sorted list of endpoints
        """
        endpoints = list(self._endpoints.values())

        # Sort by priority score (descending)
        endpoints.sort(key=self._calculate_priority, reverse=True)

        if top:
            return endpoints[:top]

        return endpoints

    def get_by_parameter(self, param_name: str) -> List[Endpoint]:
        """
        Get all endpoints with a specific parameter.

        Args:
            param_name: Parameter name to search for

        Returns:
            List of endpoints containing the parameter
        """
        results = []
        for endpoint in self._endpoints.values():
            if param_name in endpoint.parameters:
                results.append(endpoint)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get endpoint statistics.

        Returns:
            Dictionary with statistics
        """
        return {
            "total_discovered": self.stats.total_discovered,
            "unique_endpoints": self.stats.unique_endpoints,
            "duplicate_count": self.stats.duplicate_count,
            "filtered_out_of_scope": self.stats.filtered_out_of_scope,
            "deduplication_rate": (
                self.stats.duplicate_count / self.stats.total_discovered
                if self.stats.total_discovered > 0
                else 0.0
            ),
            "by_source": dict(self.stats.by_source),
            "by_method": dict(self.stats.by_method),
        }

    def _generate_signature(self, endpoint: Endpoint) -> str:
        """
        Generate unique signature for endpoint deduplication.

        The signature includes:
        1. Normalized URL (params sorted)
        2. HTTP method
        3. Parameter names (not values)

        Args:
            endpoint: Endpoint object

        Returns:
            Unique signature string
        """
        # Parse URL
        parsed = urlparse(endpoint.url)

        # Normalize query parameters (sort by key)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_params = sorted(query_params.items())
        normalized_query = urlencode(sorted_params, doseq=True)

        # Rebuild normalized URL (without fragment)
        normalized_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            normalized_query,
            '',  # Remove fragment
        ))

        # Include method and parameter names in signature
        param_names = sorted(endpoint.parameters.keys()) if endpoint.parameters else []
        param_signature = ','.join(param_names)

        # Generate hash
        signature_string = f"{endpoint.method}:{normalized_url}:{param_signature}"
        signature_hash = hashlib.sha256(signature_string.encode()).hexdigest()[:16]

        return signature_hash

    def _is_in_scope(self, url: str) -> bool:
        """
        Check if URL is in scope.

        Args:
            url: URL to check

        Returns:
            True if in scope, False otherwise
        """
        if not self.allowed_domains:
            return True  # No scope restriction

        parsed = urlparse(url)
        domain = parsed.netloc

        # Check if domain matches any allowed domain
        for allowed in self.allowed_domains:
            if domain == allowed or domain.endswith(f'.{allowed}'):
                return True

        return False

    def _has_excluded_extension(self, url: str) -> bool:
        """
        Check if URL has excluded file extension.

        Args:
            url: URL to check

        Returns:
            True if has excluded extension, False otherwise
        """
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        for ext in self.exclude_extensions:
            if path_lower.endswith(ext):
                return True

        return False

    def _calculate_priority(self, endpoint: Endpoint) -> float:
        """
        Calculate priority score for endpoint.

        Higher score = higher priority for scanning.

        Args:
            endpoint: Endpoint object

        Returns:
            Priority score (higher is better)
        """
        score = 0.0

        # Factor 1: Number of parameters (more params = more attack surface)
        param_count = len(endpoint.parameters) if endpoint.parameters else 0
        score += param_count * 10

        # Factor 2: HTTP method priority
        method_scores = {
            'POST': 20,
            'PUT': 15,
            'PATCH': 15,
            'DELETE': 10,
            'GET': 5,
        }
        score += method_scores.get(endpoint.method.upper(), 0)

        # Factor 3: Source priority (network intercept is more reliable)
        source_scores = {
            'network': 15,
            'crawler': 10,
            'static': 5,
        }
        score += source_scores.get(endpoint.source, 0)

        # Factor 4: Interesting parameter names (common vulnerability patterns)
        interesting_params = [
            'id', 'user', 'admin', 'file', 'path', 'url', 'redirect',
            'callback', 'return', 'next', 'goto', 'dest', 'target',
            'search', 'query', 'q', 'cmd', 'exec', 'upload'
        ]

        if endpoint.parameters:
            for param in endpoint.parameters.keys():
                param_lower = param.lower()
                for interesting in interesting_params:
                    if interesting in param_lower:
                        score += 5
                        break

        return score

    def clear(self):
        """Clear all endpoints and reset statistics"""
        self._endpoints.clear()
        self._url_to_signatures.clear()
        self.stats = EndpointStats()
        self.logger.info("endpoints_cleared")

    def __len__(self) -> int:
        """Return number of unique endpoints"""
        return len(self._endpoints)

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"EndpointManager("
            f"unique={self.stats.unique_endpoints}, "
            f"duplicates={self.stats.duplicate_count}, "
            f"out_of_scope={self.stats.filtered_out_of_scope})"
        )
