"""
Crawler module - Dynamic and static web crawling.

This package contains crawling engines for endpoint discovery:
- PlaywrightCrawler: Dynamic JavaScript-aware crawling
- StaticCrawler: Archive-based crawling (Wayback Machine, etc.)
- EndpointManager: Deduplication and prioritization
"""

from .playwright_crawler import PlaywrightCrawler, Endpoint
from .endpoint_manager import EndpointManager, EndpointStats
from .static_crawler import StaticCrawler


__all__ = [
    # Crawlers
    "PlaywrightCrawler",
    "StaticCrawler",
    # Data structures
    "Endpoint",
    "EndpointManager",
    "EndpointStats",
]
