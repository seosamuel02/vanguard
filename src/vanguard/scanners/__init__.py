"""
Vulnerability scanners module.

This package contains all vulnerability detection scanners.
Each scanner inherits from BaseScanner and implements the scan() method.

Available scanners:
- XSSScanner: Cross-Site Scripting detection (Dalfox + XSStrike)
- SSRFScanner: Server-Side Request Forgery (Week 3)
- IDORScanner: Insecure Direct Object Reference (Week 3)
"""

from .base_scanner import (
    BaseScanner,
    Vulnerability,
    VulnerabilityType,
    SeverityLevel,
    ScannerError,
    ScannerTimeoutError,
    ScannerRateLimitError,
)

from .xss_scanner import XSSScanner


__all__ = [
    # Base classes
    "BaseScanner",
    "Vulnerability",
    "VulnerabilityType",
    "SeverityLevel",
    # Exceptions
    "ScannerError",
    "ScannerTimeoutError",
    "ScannerRateLimitError",
    # Scanners
    "XSSScanner",
]
