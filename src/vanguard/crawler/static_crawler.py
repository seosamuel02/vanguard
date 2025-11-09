"""
Static Crawler - Integration with ParamSpider and Waybackurls.

This module wraps external static crawling tools to discover endpoints
from archived sources (Wayback Machine, Common Crawl, etc.) and parameter
extraction.

Tools integrated:
- ParamSpider: Parameter discovery
- Waybackurls: Wayback Machine URLs
- (GAU and Katana deferred to v2.0)

Reference: @docs/ai-context/wbs.md:71-75
"""

import asyncio
import shutil
import tempfile
from typing import List, Set, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import structlog

from .playwright_crawler import Endpoint


class StaticCrawler:
    """
    Static crawler using archived and indexed data sources.

    Unlike dynamic crawlers (Playwright), static crawlers don't execute
    JavaScript but gather URLs from:
    1. Wayback Machine (waybackurls)
    2. URL parameter mining (ParamSpider)

    Example:
        >>> crawler = StaticCrawler(domain="example.com")
        >>> await crawler.initialize()
        >>> endpoints = await crawler.crawl()
        >>> print(f"Found {len(endpoints)} endpoints")
    """

    def __init__(
        self,
        domain: str,
        waybackurls_path: str = "waybackurls",
        paramspider_enabled: bool = True,
        max_urls: int = 1000,
    ):
        """
        Initialize static crawler.

        Args:
            domain: Target domain to crawl
            waybackurls_path: Path to waybackurls binary
            paramspider_enabled: Enable ParamSpider (Python tool)
            max_urls: Maximum URLs to fetch (per tool)
        """
        self.domain = domain
        self.waybackurls_path = waybackurls_path
        self.paramspider_enabled = paramspider_enabled
        self.max_urls = max_urls

        # Tool availability
        self.waybackurls_available = False
        self.paramspider_available = False

        # Results
        self.discovered_urls: Set[str] = set()

        # Logging
        self.logger = structlog.get_logger(__name__)

    async def initialize(self):
        """Check if static crawling tools are installed"""
        # Check waybackurls
        self.waybackurls_available = shutil.which(self.waybackurls_path) is not None
        if self.waybackurls_available:
            self.logger.info("waybackurls_found", path=shutil.which(self.waybackurls_path))
        else:
            self.logger.warning(
                "waybackurls_not_found",
                message="Install with: go install github.com/tomnomnom/waybackurls@latest"
            )

        # Check ParamSpider (Python package)
        if self.paramspider_enabled:
            try:
                import paramspider
                self.paramspider_available = True
                self.logger.info("paramspider_found")
            except ImportError:
                self.logger.warning(
                    "paramspider_not_found",
                    message="Install with: pip install paramspider"
                )
                self.paramspider_available = False

        # Log overall status
        if not self.waybackurls_available and not self.paramspider_available:
            self.logger.error(
                "no_static_tools_available",
                message="Install waybackurls or ParamSpider for static crawling"
            )

    async def crawl(self) -> List[Endpoint]:
        """
        Run all static crawlers and collect endpoints.

        Returns:
            List of discovered Endpoint objects
        """
        all_endpoints = []

        # Run waybackurls
        if self.waybackurls_available:
            try:
                urls = await self._crawl_waybackurls()
                endpoints = self._urls_to_endpoints(urls, source="waybackurls")
                all_endpoints.extend(endpoints)
                self.logger.info(
                    "waybackurls_complete",
                    urls=len(urls),
                    endpoints=len(endpoints)
                )
            except Exception as e:
                self.logger.error(
                    "waybackurls_failed",
                    error=str(e),
                    exc_info=True
                )

        # Run ParamSpider
        if self.paramspider_available:
            try:
                urls = await self._crawl_paramspider()
                endpoints = self._urls_to_endpoints(urls, source="paramspider")
                all_endpoints.extend(endpoints)
                self.logger.info(
                    "paramspider_complete",
                    urls=len(urls),
                    endpoints=len(endpoints)
                )
            except Exception as e:
                self.logger.error(
                    "paramspider_failed",
                    error=str(e),
                    exc_info=True
                )

        self.logger.info(
            "static_crawl_complete",
            total_endpoints=len(all_endpoints),
            unique_urls=len(self.discovered_urls)
        )

        return all_endpoints

    async def _crawl_waybackurls(self) -> List[str]:
        """
        Fetch URLs from Wayback Machine using waybackurls.

        Returns:
            List of discovered URLs
        """
        self.logger.info("running_waybackurls", domain=self.domain)

        # Create temp file for output
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.txt',
            delete=False
        ) as tmp_file:
            output_file = tmp_file.name

        try:
            # Run waybackurls
            # Command: echo "example.com" | waybackurls
            process = await asyncio.create_subprocess_exec(
                self.waybackurls_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=self.domain.encode()),
                timeout=120  # 2 minutes timeout
            )

            # Parse output (one URL per line)
            urls = []
            for line in stdout.decode('utf-8', errors='ignore').splitlines():
                line = line.strip()
                if line and line.startswith('http'):
                    urls.append(line)

                    # Limit URLs
                    if len(urls) >= self.max_urls:
                        self.logger.warning(
                            "waybackurls_limit_reached",
                            limit=self.max_urls
                        )
                        break

            self.discovered_urls.update(urls)
            return urls

        except asyncio.TimeoutError:
            self.logger.error("waybackurls_timeout", domain=self.domain)
            return []

        except Exception as e:
            self.logger.error(
                "waybackurls_error",
                error=str(e),
                exc_info=True
            )
            return []

        finally:
            # Clean up temp file
            try:
                Path(output_file).unlink(missing_ok=True)
            except Exception:
                pass

    async def _crawl_paramspider(self) -> List[str]:
        """
        Fetch URLs with parameters using ParamSpider.

        ParamSpider finds URLs with GET/POST parameters which are
        prime targets for XSS/SSRF/IDOR testing.

        Returns:
            List of discovered URLs with parameters
        """
        self.logger.info("running_paramspider", domain=self.domain)

        try:
            # ParamSpider is a Python package, import and use directly
            import paramspider.main as paramspider_main

            # Create temp directory for output
            temp_dir = tempfile.mkdtemp()

            # Run ParamSpider in subprocess (it writes to files)
            # paramspider --domain example.com --output temp/
            process = await asyncio.create_subprocess_exec(
                "python", "-m", "paramspider",
                "--domain", self.domain,
                "--output", temp_dir,
                "--level", "2",  # Crawl depth
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=180  # 3 minutes timeout
            )

            # Read output file (paramspider creates <domain>.txt)
            output_file = Path(temp_dir) / f"{self.domain}.txt"
            urls = []

            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and line.startswith('http'):
                            urls.append(line)

                            # Limit URLs
                            if len(urls) >= self.max_urls:
                                self.logger.warning(
                                    "paramspider_limit_reached",
                                    limit=self.max_urls
                                )
                                break

            self.discovered_urls.update(urls)
            return urls

        except ImportError:
            self.logger.error("paramspider_import_failed")
            return []

        except asyncio.TimeoutError:
            self.logger.error("paramspider_timeout", domain=self.domain)
            return []

        except Exception as e:
            self.logger.error(
                "paramspider_error",
                error=str(e),
                exc_info=True
            )
            return []

    def _urls_to_endpoints(
        self,
        urls: List[str],
        source: str
    ) -> List[Endpoint]:
        """
        Convert raw URLs to Endpoint objects.

        Args:
            urls: List of URLs
            source: Source identifier (e.g., "waybackurls", "paramspider")

        Returns:
            List of Endpoint objects
        """
        endpoints = []

        for url in urls:
            try:
                # Parse URL
                parsed = urlparse(url)

                # Extract parameters from query string
                params = {}
                if parsed.query:
                    query_params = parse_qs(parsed.query, keep_blank_values=True)
                    # Flatten to single values (take first value if multiple)
                    params = {k: v[0] if v else '' for k, v in query_params.items()}

                # Create Endpoint
                endpoint = Endpoint(
                    url=url,
                    method="GET",  # Static crawlers only find GET URLs
                    parameters=params,
                    source=source
                )

                endpoints.append(endpoint)

            except Exception as e:
                self.logger.warning(
                    "url_parse_failed",
                    url=url,
                    error=str(e)
                )
                continue

        return endpoints

    def get_statistics(self) -> dict:
        """
        Get static crawler statistics.

        Returns:
            Dictionary with statistics
        """
        return {
            "tools_available": {
                "waybackurls": self.waybackurls_available,
                "paramspider": self.paramspider_available,
            },
            "discovered_urls": len(self.discovered_urls),
            "domain": self.domain,
        }

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"StaticCrawler("
            f"domain={self.domain}, "
            f"waybackurls={self.waybackurls_available}, "
            f"paramspider={self.paramspider_available}, "
            f"urls={len(self.discovered_urls)})"
        )
