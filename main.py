#!/usr/bin/env python3
"""
VANGUARD - Bug Bounty Automation Scanner

Main entry point for the scanner CLI.

Usage:
    python main.py scan --target https://example.com --mode stealth
    python main.py scan --config config/default.yaml
"""

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.vanguard.core.orchestrator import Orchestrator
from src.vanguard.core.rate_limiter import AdaptiveRateLimiter, RateLimitConfig
from src.vanguard.crawler.playwright_crawler import PlaywrightCrawler


console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="VANGUARD")
def cli():
    """
    VANGUARD - Bug Bounty Automation Scanner

    Intelligent web vulnerability scanner that mimics human behavior
    to avoid WAF/IDS detection.
    """
    pass


@cli.command()
@click.option('--target', required=True, help='Target URL to scan')
@click.option('--mode', default='normal', type=click.Choice(['normal', 'stealth']),
              help='Scan mode (normal or stealth)')
@click.option('--max-depth', default=3, type=int, help='Maximum crawl depth')
@click.option('--max-urls', default=500, type=int, help='Maximum URLs to crawl')
@click.option('--headless/--no-headless', default=True, help='Run browser in headless mode')
def scan(target: str, mode: str, max_depth: int, max_urls: int, headless: bool):
    """
    Start vulnerability scan on target URL.

    Example:
        python main.py scan --target https://example.com --mode stealth
    """
    console.print(f"[bold cyan]VANGUARD Scanner v1.0.0[/bold cyan]")
    console.print(f"[yellow]⚠ Week 1 Prototype - Crawler Only[/yellow]\n")

    console.print(f"[green]Target:[/green] {target}")
    console.print(f"[green]Mode:[/green] {mode}")
    console.print(f"[green]Max Depth:[/green] {max_depth}")
    console.print(f"[green]Max URLs:[/green] {max_urls}\n")

    # Run async scan
    asyncio.run(run_scan(target, mode, max_depth, max_urls, headless))


async def run_scan(target: str, mode: str, max_depth: int, max_urls: int, headless: bool):
    """
    Run the actual scan (async).
    """
    console.print("[bold]Initializing crawler...[/bold]")

    # Initialize crawler
    crawler = PlaywrightCrawler(
        target=target,
        headless=headless,
        max_depth=max_depth,
        max_urls=max_urls,
    )

    try:
        # Initialize Playwright
        await crawler.initialize()
        console.print("[green]✓ Crawler initialized[/green]\n")

        # Start crawling
        console.print(f"[bold]Starting crawl of {target}...[/bold]")
        endpoints = await crawler.crawl()

        # Display results
        console.print(f"\n[bold green]✓ Crawl completed![/bold green]\n")

        # Statistics table
        stats = crawler.get_stats()
        table = Table(title="Crawl Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Target", stats["target"])
        table.add_row("URLs Visited", str(stats["urls_visited"]))
        table.add_row("Endpoints Discovered", str(stats["endpoints_discovered"]))
        table.add_row("Network Requests", str(stats["network_requests"]))
        table.add_row("Max Depth", str(stats["max_depth"]))

        console.print(table)

        # Show sample endpoints
        if endpoints:
            console.print(f"\n[bold]Sample Endpoints:[/bold]")
            for i, endpoint in enumerate(endpoints[:10], 1):
                console.print(f"{i}. [{endpoint.method}] {endpoint.url} ({endpoint.source})")

            if len(endpoints) > 10:
                console.print(f"... and {len(endpoints) - 10} more")

        console.print(f"\n[yellow]⚠ Note: Week 1 prototype - vulnerability scanning not yet implemented[/yellow]")

    except Exception as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise

    finally:
        # Cleanup
        await crawler.close()
        console.print("\n[green]✓ Crawler closed[/green]")


@cli.command()
def version():
    """Show version information"""
    console.print("[bold cyan]VANGUARD Scanner[/bold cyan]")
    console.print("Version: 1.0.0")
    console.print("Status: Week 1 Prototype")
    console.print("\n[yellow]Implemented:[/yellow]")
    console.print("  ✓ Core orchestrator")
    console.print("  ✓ Adaptive rate limiter")
    console.print("  ✓ Playwright crawler")
    console.print("  ✓ Network interception")
    console.print("\n[yellow]Coming in Week 2:[/yellow]")
    console.print("  - XSS scanner (Dalfox + XSStrike)")
    console.print("  - Static crawler integration")
    console.print("  - Endpoint manager")


if __name__ == '__main__':
    cli()
