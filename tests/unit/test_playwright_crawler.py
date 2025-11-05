"""
Unit tests for PlaywrightCrawler module.

Run with: pytest tests/unit/test_playwright_crawler.py -v
"""

import pytest
from src.vanguard.crawler.playwright_crawler import PlaywrightCrawler, Endpoint


class TestEndpoint:
    """Test suite for Endpoint dataclass"""

    def test_endpoint_creation(self):
        """Test endpoint creation with defaults"""
        endpoint = Endpoint(url="https://example.com/test")

        assert endpoint.url == "https://example.com/test"
        assert endpoint.method == "GET"
        assert endpoint.parameters == {}
        assert endpoint.source == "crawler"

    def test_endpoint_with_parameters(self):
        """Test endpoint creation with parameters"""
        endpoint = Endpoint(
            url="https://example.com/api",
            method="POST",
            parameters={"id": "123"},
            source="network"
        )

        assert endpoint.url == "https://example.com/api"
        assert endpoint.method == "POST"
        assert endpoint.parameters == {"id": "123"}
        assert endpoint.source == "network"

    def test_endpoint_equality(self):
        """Test endpoint equality comparison"""
        e1 = Endpoint(url="https://example.com/test", method="GET")
        e2 = Endpoint(url="https://example.com/test", method="GET")
        e3 = Endpoint(url="https://example.com/test", method="POST")

        assert e1 == e2
        assert e1 != e3

    def test_endpoint_hashable(self):
        """Test endpoint can be added to sets"""
        e1 = Endpoint(url="https://example.com/test", method="GET")
        e2 = Endpoint(url="https://example.com/test", method="GET")
        e3 = Endpoint(url="https://example.com/other", method="GET")

        endpoint_set = {e1, e2, e3}

        # e1 and e2 are equal, so set should have 2 items
        assert len(endpoint_set) == 2


class TestPlaywrightCrawler:
    """Test suite for PlaywrightCrawler class"""

    def test_crawler_initialization(self):
        """Test crawler initializes correctly"""
        crawler = PlaywrightCrawler(
            target="https://example.com",
            headless=True,
            max_depth=3,
            max_urls=100,
        )

        assert crawler.target == "https://example.com"
        assert crawler.headless is True
        assert crawler.max_depth == 3
        assert crawler.max_urls == 100
        assert crawler.domain == "example.com"
        assert crawler.scheme == "https"

    def test_is_in_scope_same_domain(self):
        """Test URL scope checking for same domain"""
        crawler = PlaywrightCrawler(target="https://example.com")

        assert crawler._is_in_scope("https://example.com/page") is True
        assert crawler._is_in_scope("https://example.com/api/data") is True

    def test_is_in_scope_different_domain(self):
        """Test URL scope checking for different domain"""
        crawler = PlaywrightCrawler(target="https://example.com")

        assert crawler._is_in_scope("https://other.com/page") is False

    def test_is_in_scope_excluded_extensions(self):
        """Test URL scope checking excludes certain file types"""
        crawler = PlaywrightCrawler(target="https://example.com")

        assert crawler._is_in_scope("https://example.com/file.pdf") is False
        assert crawler._is_in_scope("https://example.com/image.jpg") is False
        assert crawler._is_in_scope("https://example.com/style.css") is False
        assert crawler._is_in_scope("https://example.com/script.js") is False

    def test_is_in_scope_wrong_scheme(self):
        """Test URL scope checking excludes non-HTTP schemes"""
        crawler = PlaywrightCrawler(target="https://example.com")

        assert crawler._is_in_scope("ftp://example.com/file") is False
        assert crawler._is_in_scope("javascript:void(0)") is False

    def test_get_stats(self):
        """Test get_stats() returns correct information"""
        crawler = PlaywrightCrawler(target="https://example.com", max_depth=5)

        stats = crawler.get_stats()

        assert stats["target"] == "https://example.com"
        assert stats["max_depth"] == 5
        assert "urls_visited" in stats
        assert "endpoints_discovered" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
