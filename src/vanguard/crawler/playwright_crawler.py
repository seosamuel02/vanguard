"""
Playwright Crawler - Dynamic web crawling with browser automation.

This module implements intelligent crawling using Playwright for JavaScript-heavy
web applications. It includes network interception for API endpoint discovery.

Reference: @docs/ai-context/architecture.md:21-26
"""

import asyncio
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass

from playwright.async_api import async_playwright, Browser, BrowserContext, Page
import structlog


@dataclass
class Endpoint:
    """Represents a discovered endpoint"""
    url: str
    method: str = "GET"
    parameters: Dict[str, Any] = None
    source: str = "crawler"  # 'crawler', 'network', 'static'

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}

    def __hash__(self):
        """Make Endpoint hashable for deduplication"""
        return hash((self.url, self.method))

    def __eq__(self, other):
        """Equality check for deduplication"""
        if not isinstance(other, Endpoint):
            return False
        return self.url == other.url and self.method == other.method


class PlaywrightCrawler:
    """
    Asynchronous web crawler using Playwright.

    Features:
    1. JavaScript execution support
    2. Network request interception (API endpoint discovery)
    3. DOM traversal for link discovery
    4. Form detection and parameter extraction
    5. Stealth mode support (Week 4 integration)

    Example:
        >>> crawler = PlaywrightCrawler(target="https://example.com")
        >>> await crawler.initialize()
        >>> endpoints = await crawler.crawl(max_depth=3)
        >>> await crawler.close()
    """

    def __init__(
        self,
        target: str,
        headless: bool = True,
        max_depth: int = 3,
        max_urls: int = 500,
    ):
        """
        Initialize the Playwright crawler.

        Args:
            target: Target URL to crawl
            headless: Run browser in headless mode
            max_depth: Maximum crawl depth
            max_urls: Maximum number of URLs to crawl
        """
        self.target = target
        self.headless = headless
        self.max_depth = max_depth
        self.max_urls = max_urls

        # Parse target domain for scope limiting
        parsed = urlparse(target)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme

        # State tracking
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[Endpoint] = set()
        self.network_requests: List[Dict[str, Any]] = []

        # Playwright instances
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None

        # Logging
        self.logger = structlog.get_logger(__name__)

    async def initialize(self):
        """Initialize Playwright browser and context"""
        self.logger.info(
            "initializing_crawler",
            target=self.target,
            headless=self.headless,
            max_depth=self.max_depth,
        )

        self.playwright = await async_playwright().start()

        # Launch browser (Chromium by default)
        self.browser = await self.playwright.chromium.launch(headless=self.headless)

        # Create browser context
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        )

        self.logger.info("crawler_initialized")

    async def crawl(self, max_depth: Optional[int] = None) -> List[Endpoint]:
        """
        Start crawling from the target URL.

        Args:
            max_depth: Override default max depth

        Returns:
            List of discovered endpoints

        Raises:
            RuntimeError: If crawler not initialized
        """
        if not self.context:
            raise RuntimeError("Crawler not initialized. Call initialize() first.")

        depth = max_depth or self.max_depth

        self.logger.info("crawl_started", target=self.target, max_depth=depth)

        # Start BFS crawling
        await self._crawl_bfs(self.target, depth=0, max_depth=depth)

        self.logger.info(
            "crawl_completed",
            urls_visited=len(self.visited_urls),
            endpoints_discovered=len(self.discovered_endpoints),
            network_requests=len(self.network_requests),
        )

        return list(self.discovered_endpoints)

    async def _crawl_bfs(self, url: str, depth: int, max_depth: int):
        """
        Breadth-first search crawling.

        Args:
            url: URL to crawl
            depth: Current depth
            max_depth: Maximum depth to crawl
        """
        # Base cases
        if depth > max_depth:
            return
        if url in self.visited_urls:
            return
        if len(self.visited_urls) >= self.max_urls:
            return
        if not self._is_in_scope(url):
            return

        # Mark as visited
        self.visited_urls.add(url)

        try:
            # Create new page
            page = await self.context.new_page()

            # Set up network interception (Week 1 prototype)
            page.on('request', lambda request: self._capture_network_request(request))

            # Navigate to URL
            self.logger.debug("navigating", url=url, depth=depth)
            await page.goto(url, wait_until='domcontentloaded', timeout=30000)

            # Wait for JavaScript to execute
            await asyncio.sleep(1)

            # Extract links from page
            links = await self._extract_links(page)

            # Add current URL as endpoint
            self.discovered_endpoints.add(Endpoint(url=url, source='crawler'))

            # Close page
            await page.close()

            # Recursively crawl discovered links
            for link in links:
                if len(self.visited_urls) < self.max_urls:
                    await self._crawl_bfs(link, depth + 1, max_depth)

        except Exception as e:
            self.logger.error("crawl_error", url=url, error=str(e))

    async def _extract_links(self, page: Page) -> List[str]:
        """
        Extract all links from the current page.

        Args:
            page: Playwright page object

        Returns:
            List of absolute URLs
        """
        try:
            # JavaScript to extract all links
            links = await page.evaluate("""
                () => {
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    return links.map(a => a.href);
                }
            """)

            # Filter and normalize links
            normalized_links = []
            for link in links:
                # Convert to absolute URL
                absolute_url = urljoin(self.target, link)

                # Remove fragments
                if '#' in absolute_url:
                    absolute_url = absolute_url.split('#')[0]

                # Check scope
                if self._is_in_scope(absolute_url):
                    normalized_links.append(absolute_url)

            self.logger.debug("links_extracted", count=len(normalized_links))
            return normalized_links

        except Exception as e:
            self.logger.error("link_extraction_error", error=str(e))
            return []

    def _capture_network_request(self, request):
        """
        Capture network requests for API endpoint discovery.

        This is a Week 1 prototype. Full implementation in Week 2.

        Args:
            request: Playwright request object
        """
        # Filter for API-like requests
        if request.resource_type in ['xhr', 'fetch']:
            self.network_requests.append({
                'url': request.url,
                'method': request.method,
                'resource_type': request.resource_type,
            })

            # Add as endpoint
            self.discovered_endpoints.add(
                Endpoint(
                    url=request.url,
                    method=request.method,
                    source='network'
                )
            )

            self.logger.debug(
                "network_request_captured",
                url=request.url,
                method=request.method,
            )

    def _is_in_scope(self, url: str) -> bool:
        """
        Check if URL is within crawling scope.

        Args:
            url: URL to check

        Returns:
            True if URL is in scope
        """
        parsed = urlparse(url)

        # Must be same domain
        if parsed.netloc != self.domain:
            return False

        # Must be HTTP/HTTPS
        if parsed.scheme not in ['http', 'https']:
            return False

        # Exclude common non-HTML files
        excluded_extensions = ['.pdf', '.zip', '.exe', '.jpg', '.png', '.gif', '.css', '.js']
        if any(url.lower().endswith(ext) for ext in excluded_extensions):
            return False

        return True

    async def close(self):
        """Close Playwright browser and cleanup"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

        self.logger.info("crawler_closed")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get crawler statistics.

        Returns:
            Dictionary with statistics
        """
        return {
            "target": self.target,
            "urls_visited": len(self.visited_urls),
            "endpoints_discovered": len(self.discovered_endpoints),
            "network_requests": len(self.network_requests),
            "max_depth": self.max_depth,
            "max_urls": self.max_urls,
        }
