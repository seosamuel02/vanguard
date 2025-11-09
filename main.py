#!/usr/bin/env python3
"""
VANGUARD - Bug Bounty Automation Scanner

Main entry point for the integrated scanner CLI.

Usage:
    python main.py scan --target https://example.com
    python main.py scan --target https://example.com --max-depth 5 --enable-xss
"""

import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.vanguard.core.integrated_scanner import IntegratedScanner, ScanConfig


console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="VANGUARD")
def cli():
    """
    VANGUARD - Integrated Bug Bounty Scanner

    Automatically crawls, scans, and reports vulnerabilities.
    """
    pass


@cli.command()
@click.option('--target', required=True, help='Target URL to scan')
@click.option('--max-depth', default=3, type=int, help='Maximum crawl depth (default: 3)')
@click.option('--max-urls', default=500, type=int, help='Maximum URLs to crawl (default: 500)')
@click.option('--headless/--no-headless', default=True, help='Run browser in headless mode')
@click.option('--enable-xss/--no-xss', default=True, help='Enable XSS scanner (default: enabled)')
@click.option('--enable-static/--no-static', default=True, help='Enable static crawler (default: enabled)')
@click.option('--dalfox-path', default='dalfox', help='Path to dalfox binary')
@click.option('--rate-limit', default=1/3, type=float, help='Requests per second (default: 0.33 = 1 req/3sec)')
@click.option('--output', type=click.Path(), help='Save results to JSON file')
def scan(
    target: str,
    max_depth: int,
    max_urls: int,
    headless: bool,
    enable_xss: bool,
    enable_static: bool,
    dalfox_path: str,
    rate_limit: float,
    output: str,
):
    """
    Start integrated vulnerability scan on target URL.

    This runs the complete VANGUARD pipeline:
    1. Dynamic crawling (Playwright)
    2. Static crawling (Wayback Machine - optional)
    3. Endpoint deduplication
    4. XSS vulnerability scanning (optional)
    5. Results reporting

    Example:
        python main.py scan --target https://example.com
        python main.py scan --target https://example.com --max-depth 5 --enable-xss
    """
    # Banner
    console.print("\n" + "=" * 80)
    console.print("VANGUARD - Integrated Bug Bounty Scanner")
    console.print("=" * 80 + "\n")

    console.print(f"[green]Target:[/green] {target}")
    console.print(f"[green]Max Depth:[/green] {max_depth}")
    console.print(f"[green]Max URLs:[/green] {max_urls}")
    console.print(f"[green]Headless:[/green] {headless}")
    console.print(f"[green]XSS Scanner:[/green] {'[bold green]Enabled[/bold green]' if enable_xss else '[dim]Disabled[/dim]'}")
    console.print(f"[green]Static Crawler:[/green] {'[bold green]Enabled[/bold green]' if enable_static else '[dim]Disabled[/dim]'}")
    console.print(f"[green]Rate Limit:[/green] {rate_limit:.2f} req/sec")
    console.print()

    # Run async scan
    asyncio.run(run_integrated_scan(
        target=target,
        max_depth=max_depth,
        max_urls=max_urls,
        headless=headless,
        enable_xss=enable_xss,
        enable_static=enable_static,
        dalfox_path=dalfox_path,
        rate_limit=rate_limit,
        output=output,
    ))


async def run_integrated_scan(
    target: str,
    max_depth: int,
    max_urls: int,
    headless: bool,
    enable_xss: bool,
    enable_static: bool,
    dalfox_path: str,
    rate_limit: float,
    output: str,
):
    """
    Run the integrated scan pipeline.
    """
    # Create scan configuration
    config = ScanConfig(
        max_crawl_depth=max_depth,
        max_urls=max_urls,
        enable_static_crawler=enable_static,
        enable_xss_scanner=enable_xss,
        dalfox_path=dalfox_path,
        requests_per_second=rate_limit,
        headless=headless,
    )

    # Bug bounty headers
    bugbounty_headers = {
        "bugbounty": "[VANGUARD] Automated Security Scanner - Educational/Research",
        "User-Agent": "VANGUARD/1.0 Security Research Tool",
    }

    # Initialize integrated scanner
    scanner = IntegratedScanner(
        target=target,
        config=config,
        bugbounty_headers=bugbounty_headers,
    )

    try:
        # Run scan with progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            task = progress.add_task("[cyan]Initializing scan...", total=None)

            # Run the scan
            vulnerabilities = await scanner.scan()

            progress.update(task, description="[green]Scan complete!")

        # Display results
        console.print("\n" + "=" * 80)
        console.print(scanner.get_summary())

        # Detailed vulnerabilities
        if vulnerabilities:
            console.print("\n[bold red]DISCOVERED VULNERABILITIES[/bold red]")
            console.print("=" * 80 + "\n")

            for i, vuln in enumerate(vulnerabilities, 1):
                console.print(f"[bold yellow][{i}] {vuln.vuln_type.value.upper()}[/bold yellow]")
                console.print(f"  URL: {vuln.url}")
                console.print(f"  Parameter: {vuln.parameter}")
                console.print(f"  Severity: [{'red' if vuln.severity.value == 'high' else 'yellow'}]{vuln.severity.value.upper()}[/]")
                console.print(f"  Confidence: {vuln.confidence:.1%}")
                console.print(f"  Payload: {vuln.payload}")
                if vuln.poc_url:
                    console.print(f"  POC: {vuln.poc_url}")
                if vuln.evidence:
                    console.print(f"  Evidence: {vuln.evidence[:100]}...")
                console.print(f"  Scanner: {vuln.scanner_name}")
                console.print()

        # Save to file if requested
        if output:
            results = scanner.get_results()
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)

            console.print(f"\n[green]Results saved to:[/green] {output_path}")

        console.print("\n" + "=" * 80)
        console.print("[bold green]Scan complete![/bold green]")
        console.print("=" * 80 + "\n")

    except KeyboardInterrupt:
        console.print("\n\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)

    except Exception as e:
        console.print(f"\n[bold red]Error during scan:[/bold red] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
def version():
    """Show version information and capabilities"""
    console.print("\n[bold cyan]VANGUARD Scanner v1.0.0[/bold cyan]")
    console.print("[cyan]Integrated Bug Bounty Automation[/cyan]\n")

    # Status table
    table = Table(title="Module Status")
    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Status", style="green")
    table.add_column("Notes", style="yellow")

    table.add_row("Core Orchestrator", "[green]✓ Complete[/green]", "Async task management")
    table.add_row("Rate Limiter", "[green]✓ Complete[/green]", "Adaptive rate control")
    table.add_row("Playwright Crawler", "[green]✓ Complete[/green]", "Dynamic JS-aware crawling")
    table.add_row("Static Crawler", "[green]✓ Complete[/green]", "Wayback Machine, ParamSpider")
    table.add_row("Endpoint Manager", "[green]✓ Complete[/green]", "Deduplication & prioritization")
    table.add_row("XSS Scanner", "[green]✓ Complete[/green]", "Dalfox integration")
    table.add_row("SSRF Scanner", "[yellow]Week 3[/yellow]", "Interactsh OOB")
    table.add_row("IDOR Scanner", "[yellow]Week 3[/yellow]", "Multi-session testing")
    table.add_row("Browser Verifier", "[yellow]Week 4[/yellow]", "POC verification")
    table.add_row("Stealth Features", "[yellow]Week 4[/yellow]", "UA rotation, delays")

    console.print(table)
    console.print()


@cli.command()
@click.argument('target')
def quick(target: str):
    """
    Quick scan with default settings.

    Example:
        python main.py quick https://example.com
    """
    console.print(f"\n[cyan]Running quick scan on {target}...[/cyan]\n")

    # Run with default settings
    asyncio.run(run_integrated_scan(
        target=target,
        max_depth=2,  # Faster
        max_urls=100,  # Limited
        headless=True,
        enable_xss=True,
        enable_static=False,  # Skip for speed
        dalfox_path='dalfox',
        rate_limit=1/2,  # Faster (1 req/2sec)
        output=None,
    ))


if __name__ == '__main__':
    cli()
