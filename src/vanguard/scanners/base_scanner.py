"""
Base Scanner - Abstract base class for all vulnerability scanners.

This module defines the common interface and shared functionality for all
vulnerability detection modules (XSS, SSRF, IDOR, etc.).

Design Pattern: Strategy Pattern
Reference: @docs/ai-context/architecture.md:107-123
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import structlog


class VulnerabilityType(Enum):
    """Types of vulnerabilities that can be detected"""
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SSRF_BLIND = "ssrf_blind"
    SSRF_SEMI_BLIND = "ssrf_semi_blind"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """Severity levels based on CVSS"""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    INFO = "info"          # 0.0


@dataclass
class Vulnerability:
    """
    Represents a discovered vulnerability.

    This is the core data structure that all scanners return.
    It will be used for verification, reporting, and storage.
    """

    # Core identification
    vuln_type: VulnerabilityType
    url: str
    parameter: Optional[str] = None

    # Severity and confidence
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = 0.0  # 0.0 to 1.0

    # Detection details
    payload: Optional[str] = None
    method: str = "GET"
    evidence: Optional[str] = None  # Response snippet showing vulnerability

    # POC (Proof of Concept)
    poc_url: Optional[str] = None
    poc_request: Optional[Dict[str, Any]] = None

    # Metadata
    scanner_name: str = "unknown"
    detected_at: datetime = field(default_factory=datetime.now)
    verified: bool = False  # Set to True after browser verification

    # Additional context
    description: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def __hash__(self):
        """Make Vulnerability hashable for deduplication"""
        return hash((self.vuln_type, self.url, self.parameter, self.payload))

    def __eq__(self, other):
        """Equality check for deduplication"""
        if not isinstance(other, Vulnerability):
            return False
        return (
            self.vuln_type == other.vuln_type
            and self.url == other.url
            and self.parameter == other.parameter
            and self.payload == other.payload
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "type": self.vuln_type.value,
            "url": self.url,
            "parameter": self.parameter,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "payload": self.payload,
            "method": self.method,
            "evidence": self.evidence,
            "poc_url": self.poc_url,
            "scanner": self.scanner_name,
            "detected_at": self.detected_at.isoformat(),
            "verified": self.verified,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
        }


class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanners.

    All scanners (XSS, SSRF, IDOR) must inherit from this class and
    implement the scan() method.

    Features:
    1. Unified interface for all scanners
    2. Built-in logging support
    3. Rate limiting integration
    4. Error handling

    Example:
        >>> class XSSScanner(BaseScanner):
        ...     async def scan(self, endpoint):
        ...         # XSS detection logic
        ...         return [vulnerability]

        >>> scanner = XSSScanner()
        >>> results = await scanner.scan(endpoint)
    """

    def __init__(
        self,
        scanner_name: str,
        rate_limiter: Optional[Any] = None,
        enabled: bool = True,
    ):
        """
        Initialize the base scanner.

        Args:
            scanner_name: Name of the scanner (e.g., "XSSScanner")
            rate_limiter: Rate limiter instance for request throttling
            enabled: Whether this scanner is enabled
        """
        self.scanner_name = scanner_name
        self.rate_limiter = rate_limiter
        self.enabled = enabled

        # Statistics
        self.scanned_count = 0
        self.vulnerability_count = 0

        # Logging
        self.logger = structlog.get_logger(
            __name__,
            scanner=self.scanner_name
        )

    @abstractmethod
    async def scan(self, endpoint) -> List[Vulnerability]:
        """
        Scan an endpoint for vulnerabilities.

        This is the main method that all scanners must implement.

        Args:
            endpoint: Endpoint object from the crawler

        Returns:
            List of discovered vulnerabilities (empty if none found)

        Raises:
            ScannerError: If scanning fails
        """
        pass

    async def scan_batch(self, endpoints: List) -> List[Vulnerability]:
        """
        Scan multiple endpoints in batch.

        Args:
            endpoints: List of Endpoint objects

        Returns:
            List of all discovered vulnerabilities
        """
        all_vulnerabilities = []

        for endpoint in endpoints:
            if not self.enabled:
                self.logger.info("scanner_disabled", endpoint=endpoint.url)
                continue

            try:
                # Apply rate limiting if configured
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                # Scan the endpoint
                vulnerabilities = await self.scan(endpoint)

                # Update statistics
                self.scanned_count += 1
                self.vulnerability_count += len(vulnerabilities)

                all_vulnerabilities.extend(vulnerabilities)

                # Log results
                if vulnerabilities:
                    self.logger.info(
                        "vulnerabilities_found",
                        endpoint=endpoint.url,
                        count=len(vulnerabilities),
                        types=[v.vuln_type.value for v in vulnerabilities]
                    )
                else:
                    self.logger.debug("no_vulnerabilities", endpoint=endpoint.url)

            except Exception as e:
                self.logger.error(
                    "scan_failed",
                    endpoint=endpoint.url,
                    error=str(e),
                    exc_info=True
                )
                # Continue scanning other endpoints (graceful degradation)
                continue

        return all_vulnerabilities

    def get_statistics(self) -> Dict[str, int]:
        """
        Get scanner statistics.

        Returns:
            Dictionary with scanned count and vulnerability count
        """
        return {
            "scanned": self.scanned_count,
            "vulnerabilities": self.vulnerability_count,
            "detection_rate": (
                self.vulnerability_count / self.scanned_count
                if self.scanned_count > 0
                else 0.0
            ),
        }

    def reset_statistics(self):
        """Reset scanner statistics"""
        self.scanned_count = 0
        self.vulnerability_count = 0

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"{self.scanner_name}("
            f"enabled={self.enabled}, "
            f"scanned={self.scanned_count}, "
            f"found={self.vulnerability_count})"
        )


class ScannerError(Exception):
    """Base exception for scanner errors"""
    pass


class ScannerTimeoutError(ScannerError):
    """Raised when scanner times out"""
    pass


class ScannerRateLimitError(ScannerError):
    """Raised when rate limit is exceeded"""
    pass
