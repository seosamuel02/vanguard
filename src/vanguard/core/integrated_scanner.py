"""
Integrated Scanner - Main scanning pipeline that orchestrates all modules.

This is the **REAL** integrated scanner that automatically:
1. Crawls the target (dynamic + static)
2. Deduplicates endpoints
3. Scans for vulnerabilities
4. Returns results

Usage:
    scanner = IntegratedScanner(target="https://example.com")
    results = await scanner.scan()
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

import structlog

from ..crawler import PlaywrightCrawler, EndpointManager, StaticCrawler, Endpoint
from ..scanners import XSSScanner, Vulnerability
from .rate_limiter import AdaptiveRateLimiter


class ScanConfig:
    """Configuration for integrated scanner"""

    def __init__(
        self,
        # Crawling config
        max_crawl_depth: int = 3,
        max_urls: int = 500,
        enable_static_crawler: bool = True,

        # Scanning config
        enable_xss_scanner: bool = True,
        dalfox_path: str = "dalfox",

        # Rate limiting
        requests_per_second: float = 1/3,  # 1 request per 3 seconds

        # Stealth
        headless: bool = True,
        user_agent: Optional[str] = None,
    ):
        self.max_crawl_depth = max_crawl_depth
        self.max_urls = max_urls
        self.enable_static_crawler = enable_static_crawler
        self.enable_xss_scanner = enable_xss_scanner
        self.dalfox_path = dalfox_path
        self.requests_per_second = requests_per_second
        self.headless = headless
        self.user_agent = user_agent


class IntegratedScanner:
    """
    Main integrated bug bounty scanner.

    This class orchestrates the entire scanning pipeline:
    - Crawling (Playwright + Static)
    - Endpoint management (deduplication)
    - Vulnerability scanning (XSS, SSRF, IDOR)
    - Result aggregation

    Example:
        >>> scanner = IntegratedScanner("https://example.com")
        >>> results = await scanner.scan()
        >>> print(f"Found {len(results)} vulnerabilities")
    """

    def __init__(
        self,
        target: str,
        config: Optional[ScanConfig] = None,
        bugbounty_headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize integrated scanner.

        Args:
            target: Target URL to scan
            config: Scan configuration
            bugbounty_headers: Mandatory bug bounty headers
        """
        self.target = target
        self.config = config or ScanConfig()

        # Extract domain from target
        from urllib.parse import urlparse
        parsed = urlparse(target)
        self.domain = parsed.netloc

        # Bug bounty compliance headers
        self.bugbounty_headers = bugbounty_headers or {
            "bugbounty": "[VANGUARD] Automated Security Scanner",
            "User-Agent": self.config.user_agent or "VANGUARD/1.0 Bug Bounty Scanner",
        }

        # Components
        self.endpoint_manager: Optional[EndpointManager] = None
        self.crawlers: List[Any] = []
        self.scanners: List[Any] = []

        # Results
        self.discovered_endpoints: List[Endpoint] = []
        self.vulnerabilities: List[Vulnerability] = []

        # Logging
        self.logger = structlog.get_logger(__name__)
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    async def scan(self) -> List[Vulnerability]:
        """
        Run the complete scanning pipeline.

        Returns:
            List of discovered vulnerabilities
        """
        self.logger.info(
            "scan_started",
            scan_id=self.scan_id,
            target=self.target,
            config=vars(self.config)
        )

        try:
            # Phase 1: Crawling
            await self._phase_crawling()

            # Phase 2: Endpoint Management
            await self._phase_endpoint_management()

            # Phase 3: Vulnerability Scanning
            await self._phase_vulnerability_scanning()

            self.logger.info(
                "scan_complete",
                scan_id=self.scan_id,
                endpoints=len(self.discovered_endpoints),
                vulnerabilities=len(self.vulnerabilities)
            )

            return self.vulnerabilities

        except Exception as e:
            self.logger.error(
                "scan_failed",
                scan_id=self.scan_id,
                error=str(e),
                exc_info=True
            )
            raise

    async def _phase_crawling(self):
        """Phase 1: Crawl the target to discover endpoints"""
        self.logger.info("phase_crawling_started")

        all_endpoints = []

        # Dynamic crawling with Playwright
        try:
            self.logger.info("starting_playwright_crawler")

            playwright_crawler = PlaywrightCrawler(
                target=self.target,
                headless=self.config.headless,
                max_depth=self.config.max_crawl_depth,
                max_urls=self.config.max_urls,
            )

            await playwright_crawler.initialize()
            dynamic_endpoints = await playwright_crawler.crawl()
            await playwright_crawler.close()

            all_endpoints.extend(dynamic_endpoints)
            self.logger.info(
                "playwright_crawler_complete",
                endpoints=len(dynamic_endpoints)
            )

        except Exception as e:
            self.logger.error(
                "playwright_crawler_failed",
                error=str(e),
                exc_info=True
            )

        # Static crawling (optional)
        if self.config.enable_static_crawler:
            try:
                self.logger.info("starting_static_crawler")

                static_crawler = StaticCrawler(
                    domain=self.domain,
                    max_urls=self.config.max_urls
                )

                await static_crawler.initialize()
                static_endpoints = await static_crawler.crawl()

                all_endpoints.extend(static_endpoints)
                self.logger.info(
                    "static_crawler_complete",
                    endpoints=len(static_endpoints)
                )

            except Exception as e:
                self.logger.warning(
                    "static_crawler_failed",
                    error=str(e)
                )

        self.discovered_endpoints = all_endpoints
        self.logger.info(
            "phase_crawling_complete",
            total_endpoints=len(all_endpoints)
        )

    async def _phase_endpoint_management(self):
        """Phase 2: Deduplicate and prioritize endpoints"""
        self.logger.info("phase_endpoint_management_started")

        self.endpoint_manager = EndpointManager(
            allowed_domains=[self.domain]
        )

        # Add all discovered endpoints
        added = self.endpoint_manager.add_endpoints(self.discovered_endpoints)

        # Get statistics
        stats = self.endpoint_manager.get_statistics()

        self.logger.info(
            "phase_endpoint_management_complete",
            total=stats['total_discovered'],
            unique=stats['unique_endpoints'],
            duplicates=stats['duplicate_count'],
            dedup_rate=stats['deduplication_rate']
        )

        # Update to unique endpoints only
        self.discovered_endpoints = self.endpoint_manager.get_unique_endpoints()

    async def _phase_vulnerability_scanning(self):
        """Phase 3: Scan endpoints for vulnerabilities"""
        self.logger.info("phase_vulnerability_scanning_started")

        # Initialize rate limiter
        rate_limiter = AdaptiveRateLimiter(
            max_rate=self.config.requests_per_second,
            burst_size=1
        )

        # XSS Scanner
        if self.config.enable_xss_scanner:
            try:
                self.logger.info("starting_xss_scanner")

                xss_scanner = XSSScanner(
                    dalfox_path=self.config.dalfox_path,
                    rate_limiter=rate_limiter,
                    mandatory_headers=self.bugbounty_headers,
                    timeout=60,
                )

                # Get high-priority endpoints for scanning
                priority_endpoints = self.endpoint_manager.get_by_priority(top=50)

                self.logger.info(
                    "xss_scanning_endpoints",
                    count=len(priority_endpoints)
                )

                # Scan endpoints
                xss_vulns = await xss_scanner.scan_batch(priority_endpoints)
                self.vulnerabilities.extend(xss_vulns)

                scanner_stats = xss_scanner.get_statistics()
                self.logger.info(
                    "xss_scanner_complete",
                    scanned=scanner_stats['scanned'],
                    found=scanner_stats['vulnerabilities']
                )

            except Exception as e:
                self.logger.error(
                    "xss_scanner_failed",
                    error=str(e),
                    exc_info=True
                )

        # TODO: Add SSRF Scanner (Week 3)
        # TODO: Add IDOR Scanner (Week 3)

        self.logger.info(
            "phase_vulnerability_scanning_complete",
            total_vulnerabilities=len(self.vulnerabilities)
        )

    def get_results(self) -> Dict[str, Any]:
        """
        Get scan results in structured format.

        Returns:
            Dictionary with scan results and statistics
        """
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "statistics": {
                "endpoints_discovered": len(self.discovered_endpoints),
                "vulnerabilities_found": len(self.vulnerabilities),
                "endpoint_stats": self.endpoint_manager.get_statistics() if self.endpoint_manager else {},
            },
            "vulnerabilities": [vuln.to_dict() for vuln in self.vulnerabilities],
        }

    def get_summary(self) -> str:
        """
        Get human-readable summary of scan results.

        Returns:
            Formatted summary string
        """
        stats = self.endpoint_manager.get_statistics() if self.endpoint_manager else {}

        summary = f"""
========================================
VANGUARD Scan Results
========================================
Scan ID: {self.scan_id}
Target: {self.target}

Crawling:
  • Endpoints discovered: {len(self.discovered_endpoints)}
  • Unique endpoints: {stats.get('unique_endpoints', 0)}
  • Duplicates removed: {stats.get('duplicate_count', 0)}

Vulnerability Scanning:
  • Total vulnerabilities: {len(self.vulnerabilities)}
"""

        # Group vulnerabilities by type
        if self.vulnerabilities:
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln.vuln_type.value
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

            summary += "\nVulnerabilities by Type:\n"
            for vuln_type, count in vuln_types.items():
                summary += f"  • {vuln_type}: {count}\n"
        else:
            summary += "\n  No vulnerabilities detected\n"

        summary += "========================================\n"

        return summary
