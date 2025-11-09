"""
Integration test for full scanning pipeline.

This test verifies that the entire VANGUARD pipeline works end-to-end:
1. Crawling (Playwright + Static)
2. Endpoint Management (Deduplication)
3. Scanning (XSS detection)

Test target: http://testphp.vulnweb.com (public vulnerable site)
"""

import pytest
import asyncio
from typing import List

from vanguard.crawler import (
    PlaywrightCrawler,
    StaticCrawler,
    EndpointManager,
    Endpoint
)
from vanguard.scanners import (
    XSSScanner,
    Vulnerability,
    VulnerabilityType
)
from vanguard.core.rate_limiter import RateLimiter


# Test target (public vulnerable test site)
TEST_TARGET = "http://testphp.vulnweb.com"
TEST_DOMAIN = "testphp.vulnweb.com"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_scanning_pipeline():
    """
    Test complete scanning pipeline: Crawl → Deduplicate → Scan

    This is the core integration test for Week 2.
    """
    print("\n" + "=" * 60)
    print("VANGUARD Week 2 Integration Test")
    print("=" * 60)

    # ========================================
    # Phase 1: Crawling
    # ========================================
    print("\n[Phase 1] Crawling...")

    # Dynamic crawling with Playwright
    playwright_crawler = PlaywrightCrawler(
        target=TEST_TARGET,
        headless=True,
        max_depth=2,  # Limit depth for faster testing
        max_urls=50   # Limit URLs for faster testing
    )

    await playwright_crawler.initialize()
    dynamic_endpoints = await playwright_crawler.crawl()
    await playwright_crawler.close()

    print(f"  ✓ Playwright: {len(dynamic_endpoints)} endpoints discovered")

    # Static crawling (Wayback Machine)
    static_crawler = StaticCrawler(
        domain=TEST_DOMAIN,
        max_urls=50  # Limit for faster testing
    )

    await static_crawler.initialize()
    static_endpoints = await static_crawler.crawl()

    print(f"  ✓ Static: {len(static_endpoints)} endpoints discovered")

    # ========================================
    # Phase 2: Endpoint Management
    # ========================================
    print("\n[Phase 2] Endpoint Deduplication...")

    manager = EndpointManager(
        allowed_domains=[TEST_DOMAIN]
    )

    # Add all discovered endpoints
    all_endpoints = dynamic_endpoints + static_endpoints
    manager.add_endpoints(all_endpoints)

    # Get unique endpoints
    unique_endpoints = manager.get_unique_endpoints()
    stats = manager.get_statistics()

    print(f"  ✓ Total discovered: {stats['total_discovered']}")
    print(f"  ✓ Unique endpoints: {stats['unique_endpoints']}")
    print(f"  ✓ Duplicates removed: {stats['duplicate_count']}")
    print(f"  ✓ Out of scope: {stats['filtered_out_of_scope']}")

    # Assert we found some endpoints
    assert len(unique_endpoints) > 0, "Should discover at least some endpoints"

    # Get high-priority endpoints (those with parameters)
    priority_endpoints = manager.get_by_priority(top=10)
    print(f"  ✓ High-priority endpoints: {len(priority_endpoints)}")

    # ========================================
    # Phase 3: Vulnerability Scanning
    # ========================================
    print("\n[Phase 3] XSS Scanning...")

    # Initialize rate limiter (1 request per 2 seconds - respectful)
    rate_limiter = RateLimiter(
        max_rate=1/2,  # 1 request per 2 seconds
        burst_size=1
    )

    # Initialize XSS scanner
    xss_scanner = XSSScanner(
        dalfox_path="dalfox",  # Assumes dalfox is in PATH
        rate_limiter=rate_limiter,
        mandatory_headers={
            "bugbounty": "[VANGUARD Test] Automated Security Scanner",
            "User-Agent": "VANGUARD/1.0 Integration Test"
        },
        timeout=30,  # 30 seconds per scan
    )

    # Scan top priority endpoints only (to save time)
    test_endpoints = priority_endpoints[:5]  # Top 5 endpoints
    print(f"  Scanning {len(test_endpoints)} high-priority endpoints...")

    vulnerabilities = []
    for i, endpoint in enumerate(test_endpoints, 1):
        print(f"    [{i}/{len(test_endpoints)}] Scanning: {endpoint.url[:60]}...")

        try:
            vulns = await xss_scanner.scan(endpoint)
            vulnerabilities.extend(vulns)

            if vulns:
                print(f"      → Found {len(vulns)} vulnerability(ies)!")
        except Exception as e:
            print(f"      → Scan failed: {e}")
            continue

    # ========================================
    # Phase 4: Results
    # ========================================
    print("\n[Phase 4] Results Summary")
    print("=" * 60)

    scanner_stats = xss_scanner.get_statistics()
    print(f"  Endpoints scanned: {scanner_stats['scanned']}")
    print(f"  Vulnerabilities found: {scanner_stats['vulnerabilities']}")

    if vulnerabilities:
        print(f"\n  🚨 VULNERABILITIES DETECTED:")
        for vuln in vulnerabilities:
            print(f"    • {vuln.vuln_type.value}")
            print(f"      URL: {vuln.url}")
            print(f"      Parameter: {vuln.parameter}")
            print(f"      Severity: {vuln.severity.value}")
            print(f"      Confidence: {vuln.confidence:.2f}")
            print(f"      Payload: {vuln.payload[:60]}...")
            print()
    else:
        print("  ✓ No vulnerabilities detected (or dalfox not installed)")

    print("=" * 60)
    print("Integration test complete!")
    print("=" * 60)

    # Assertions
    assert len(unique_endpoints) > 0, "Should discover endpoints"
    assert scanner_stats['scanned'] > 0, "Should scan at least one endpoint"

    # Note: We don't assert vulnerabilities > 0 because:
    # 1. Dalfox might not be installed
    # 2. Test site might be patched
    # 3. Rate limiting might skip some tests


@pytest.mark.integration
@pytest.mark.asyncio
async def test_endpoint_manager_deduplication():
    """Test that endpoint manager correctly deduplicates URLs"""
    manager = EndpointManager(allowed_domains=["example.com"])

    # Create duplicate endpoints (same URL, different order of params)
    endpoint1 = Endpoint(
        url="https://example.com/test?a=1&b=2",
        method="GET",
        parameters={"a": "1", "b": "2"},
        source="crawler"
    )

    endpoint2 = Endpoint(
        url="https://example.com/test?b=2&a=1",  # Same params, different order
        method="GET",
        parameters={"b": "2", "a": "1"},
        source="crawler"
    )

    # Add both
    added1 = manager.add_endpoint(endpoint1)
    added2 = manager.add_endpoint(endpoint2)

    # First should be added, second should be duplicate
    assert added1 is True, "First endpoint should be added"
    assert added2 is False, "Second endpoint should be duplicate"
    assert len(manager) == 1, "Should have only 1 unique endpoint"

    print("\n✓ Deduplication working correctly")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scanner_graceful_degradation():
    """Test that scanner handles missing tools gracefully"""

    # Create scanner with non-existent dalfox path
    scanner = XSSScanner(
        dalfox_path="/nonexistent/dalfox",
        enabled=True
    )

    # Scanner should auto-disable if tool not found
    # (Check in _check_tools method)

    # Try to scan - should return empty list, not crash
    test_endpoint = Endpoint(
        url="https://example.com/test?q=search",
        method="GET",
        parameters={"q": "search"},
        source="test"
    )

    vulnerabilities = await scanner.scan(test_endpoint)

    # Should return empty list when disabled, not raise exception
    assert isinstance(vulnerabilities, list), "Should return list"
    assert len(vulnerabilities) == 0, "Should return empty list when disabled"

    print("\n✓ Graceful degradation working correctly")


if __name__ == "__main__":
    # Run tests directly
    print("Running VANGUARD Week 2 Integration Tests...")
    print("=" * 60)

    # Test 1: Full pipeline
    asyncio.run(test_full_scanning_pipeline())

    # Test 2: Deduplication
    asyncio.run(test_endpoint_manager_deduplication())

    # Test 3: Graceful degradation
    asyncio.run(test_scanner_graceful_degradation())

    print("\n✅ All integration tests passed!")
