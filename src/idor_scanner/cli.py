"""
CLI Interface for the IDOR Scanner.

Provides a beautiful command-line interface using Typer and Rich.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import __version__
from .discovery import EndpointDiscovery
from .detector import IDORDetector
from .http_client import HTTPClient
from .models import AuthType, ScanConfig, UserCredentials, Endpoint
from .reporter import ReportGenerator
from .session import SessionManager
from .cookie_import import CookieImporter, load_cookies_from_file
from .bounty_mode import get_bounty_config, list_programs, get_user_agent
from .har_importer import HARImporter
from .crawler import HeadlessCrawler

# Initialize
app = typer.Typer(
    name="idor-scanner",
    help="API Access Control Scanner - Detect IDOR/BOLA vulnerabilities",
    add_completion=False,
)
console = Console()


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold blue]IDOR Scanner[/bold blue] v{__version__}")
        raise typer.Exit()


def parse_credentials(creds: str, role: str = "user") -> UserCredentials:
    """Parse credentials in format 'username:password' or 'username:password:auth_type'."""
    parts = creds.split(":")
    
    if len(parts) < 2:
        raise typer.BadParameter(
            f"Credentials must be in format 'username:password' or 'username:password:auth_type'"
        )
    
    username = parts[0]
    password = parts[1]
    auth_type = AuthType.BEARER  # default
    
    if len(parts) >= 3:
        try:
            auth_type = AuthType(parts[2].lower())
        except ValueError:
            console.print(f"[yellow]Warning: Unknown auth type '{parts[2]}', using bearer[/yellow]")
    
    return UserCredentials(
        username=username,
        password=password,
        role=role,
        auth_type=auth_type,
    )


@app.callback()
def main(
    version: bool = typer.Option(
        None, "--version", "-V", callback=version_callback, is_eager=True,
        help="Show version and exit"
    ),
) -> None:
    """
    IDOR Scanner - API Access Control Vulnerability Scanner
    
    Detects Broken Access Control vulnerabilities (IDOR/BOLA) in REST APIs
    through intelligent multi-user testing and semantic response comparison.
    """
    pass


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target API base URL (e.g., https://api.example.com)"),
    user1: str = typer.Option(
        ..., "--user1", "-u1", 
        help="First user credentials (format: username:password[:auth_type])"
    ),
    user2: str = typer.Option(
        ..., "--user2", "-u2",
        help="Second user credentials (format: username:password[:auth_type])"
    ),
    admin: Optional[str] = typer.Option(
        None, "--admin", "-a",
        help="Admin user credentials for vertical escalation testing"
    ),
    auth_endpoint: Optional[str] = typer.Option(
        None, "--auth-endpoint",
        help="Authentication endpoint path (default: /api/login)"
    ),
    openapi: Optional[str] = typer.Option(
        None, "--openapi", "-o",
        help="Path or URL to OpenAPI/Swagger spec"
    ),
    endpoints_file: Optional[str] = typer.Option(
        None, "--endpoints", "-e",
        help="File containing endpoints to test (one per line)"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-O",
        help="Output directory for reports"
    ),
    format: List[str] = typer.Option(
        ["terminal", "json"], "--format", "-f",
        help="Output formats: terminal, json, markdown, html"
    ),
    rate_limit: int = typer.Option(
        10, "--rate-limit", "-r",
        help="Requests per second limit"
    ),
    timeout: int = typer.Option(
        30, "--timeout", "-t",
        help="Request timeout in seconds"
    ),
    no_crawl: bool = typer.Option(
        False, "--no-crawl",
        help="Disable automatic API crawling"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable verbose output"
    ),
    debug: bool = typer.Option(
        False, "--debug",
        help="Enable debug output"
    ),
    # NEW OPTIONS
    cookies: Optional[str] = typer.Option(
        None, "--cookies", "-c",
        help="Path to cookies file (JSON from Cookie Editor, Netscape format, or raw string)"
    ),
    user_agent_suffix: Optional[str] = typer.Option(
        None, "--ua-suffix",
        help="Suffix to append to User-Agent (e.g., -inSec-CrowdPowered for Inditex)"
    ),
    bounty_program: Optional[str] = typer.Option(
        None, "--bounty", "-b",
        help="Bug bounty program preset (inditex, notion, doordash, tinder, nextcloud)"
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", "-p",
        help="Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)"
    ),
    har_file: Optional[str] = typer.Option(
        None, "--har",
        help="Path to HAR file (from Browser DevTools) to learn endpoints"
    ),
    headless: bool = typer.Option(
        False, "--headless",
        help="Use headless browser to crawl and learn traffic (requires Playwright)"
    ),
) -> None:
    """
    Scan an API for IDOR vulnerabilities.
    
    Requires at least 2 user accounts to test access control between users.
    
    Example:
        idor-scanner scan https://api.example.com \\
            --user1 "alice:password123" \\
            --user2 "bob:password456"
    """
    setup_logging(verbose, debug)
    
    # Apply bounty program configuration
    bounty_config = None
    if bounty_program:
        bounty_config = get_bounty_config(bounty_program)
        if bounty_config:
            console.print(f"[cyan]Using bug bounty preset: {bounty_config.name}[/cyan]")
            if bounty_config.user_agent_suffix and not user_agent_suffix:
                user_agent_suffix = bounty_config.user_agent_suffix
                console.print(f"[dim]   User-Agent suffix: {user_agent_suffix}[/dim]")
            if bounty_config.rate_limit < rate_limit:
                rate_limit = bounty_config.rate_limit
                console.print(f"[dim]   Rate limit: {rate_limit} req/s[/dim]")
        else:
            console.print(f"[yellow]Warning: Unknown bounty program '{bounty_program}'[/yellow]")
            console.print(f"[dim]Available: {', '.join(list_programs())}[/dim]")
    
    # Load cookies if provided
    imported_cookies = {}
    if cookies:
        try:
            imported_cookies = load_cookies_from_file(cookies)
            console.print(f"[green][+] Loaded {len(imported_cookies)} cookies from file[/green]")
        except Exception as e:
            console.print(f"[red]Error loading cookies: {e}[/red]")
            raise typer.Exit(1)
    
    # Parse credentials
    try:
        creds1 = parse_credentials(user1, "user")
        creds2 = parse_credentials(user2, "user")
        admin_creds = parse_credentials(admin, "admin") if admin else None
    except Exception as e:
        console.print(f"[red]Error parsing credentials: {e}[/red]")
        raise typer.Exit(1)
    
    # Build user list
    users = [creds1, creds2]
    if admin_creds:
        users.append(admin_creds)
    
    # Create config with custom headers
    custom_headers = {}
    if user_agent_suffix:
        custom_headers["User-Agent-Suffix"] = user_agent_suffix
    
    # Load endpoints from HAR if provided
    har_endpoints = []
    if har_file:
        try:
            importer = HARImporter(target_domain=target)
            har_endpoints = importer.load_file(har_file)
            console.print(f"[green][+] Loaded {len(har_endpoints)} endpoints from HAR file[/green]")
            # Check for body templates
            json_eps = sum(1 for ep in har_endpoints if ep.body_template)
            if json_eps > 0:
                console.print(f"[cyan]  Found {json_eps} endpoints with JSON body IDs[/cyan]")
        except Exception as e:
            console.print(f"[red]Error loading HAR file: {e}[/red]")
            # Don't exit, just continue without HAR? No, better warn user.
            
    # Run Headless Crawler if requested
    crawled_endpoints = []
    if headless:
        if not cookies:
             console.print("[yellow]Warning: --headless works best with --cookies to crawl authenticated areas.[/yellow]")
        
        try:
            console.print("[blue]Starting Headless Crawler...[/blue]")
            crawler = HeadlessCrawler(target)
            # Run async crawl. Since we are in sync main, we need asyncio.run or wait for the main loop?
            # main calls _run_scan which is async. 
            # Ideally we run crawler inside _run_scan? 
            # Or we run it here synchronously (via asyncio.run).
            crawled_endpoints = asyncio.run(crawler.crawl(imported_cookies))
            console.print(f"[green][+] Headless crawler found {len(crawled_endpoints)} endpoints[/green]")
        except Exception as e:
            console.print(f"[red]Crawler failed: {e}[/red]")

    # Combine known endpoints
    all_known_endpoints = []
    if bounty_config and bounty_config.known_endpoints:
        all_known_endpoints.extend(bounty_config.known_endpoints)
    if har_endpoints:
        all_known_endpoints.extend(har_endpoints)
    if crawled_endpoints:
        all_known_endpoints.extend(crawled_endpoints)
    
    config = ScanConfig(
        target=target,
        users=users,
        timeout=timeout,
        rate_limit=rate_limit,
        custom_headers=custom_headers,
        proxy=proxy,
    )
    
    # Print banner
    console.print()
    console.print(
        Panel(
            "[bold blue]IDOR SCANNER[/bold blue]\n"
            f"[dim]Target: {target}[/dim]\n"
            f"[dim]Users: {len(users)}[/dim]"
            + (f"\n[dim]Bounty: {bounty_config.name}[/dim]" if bounty_config else ""),
            border_style="blue",
        )
    )
    console.print()
    
    # Run the scan
    try:
        result = asyncio.run(_run_scan(
            config=config,
            auth_endpoint=auth_endpoint or f"{target}/api/login",
            openapi=openapi,
            endpoints_file=endpoints_file,
            crawl=not no_crawl,
            known_endpoints=all_known_endpoints or None,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        if debug:
            console.print_exception()
        raise typer.Exit(1)
    
    # Generate reports
    reporter = ReportGenerator(output_dir=output)
    
    if "terminal" in format:
        reporter.generate_terminal(result)
    
    # Save reports
    save_formats = [f for f in format if f != "terminal"]
    if save_formats:
        saved = reporter.save_reports(result, save_formats)
        console.print()
        for fmt, path in saved.items():
            console.print(f"[green]✓[/green] Saved {fmt} report: {path}")
    
    # Exit with error code if vulnerabilities found
    if result.vulnerabilities:
        raise typer.Exit(len(result.vulnerabilities))


async def _run_scan(
    config: ScanConfig,
    auth_endpoint: str,
    openapi: Optional[str],
    endpoints_file: Optional[str],
    crawl: bool,
    known_endpoints: Optional[List[Endpoint]] = None,
) -> "ScanResult":
    """Run the actual scan asynchronously."""
    
    async with HTTPClient(
        timeout=config.timeout,
        rate_limit=config.rate_limit,
        custom_headers=config.custom_headers,
        proxy=config.proxy,
    ) as http_client:
        
        session_manager = SessionManager(http_client, auth_endpoint)
        
        # Authenticate users
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            auth_task = progress.add_task("Authenticating users...", total=None)
            
            sessions = {}
            for i, user in enumerate(config.users):
                user_id = f"user{i+1}" if user.role != "admin" else "admin"
                try:
                    session = await session_manager.authenticate(
                        user_id=user_id,
                        credentials=user,
                        auth_endpoint=auth_endpoint,
                    )
                    sessions[user_id] = session
                    progress.update(
                        auth_task, 
                        description=f"✓ Authenticated: {user.username}"
                    )
                except Exception as e:
                    console.print(f"[red]Failed to authenticate {user.username}: {e}[/red]")
                    raise
            
            progress.update(auth_task, description="[green]✓ All users authenticated[/green]")
        
        # Discover endpoints
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            discover_task = progress.add_task("Discovering endpoints...", total=None)
            
            discovery = EndpointDiscovery(http_client, config.target)
            endpoints = await discovery.discover_all(
                openapi_path=openapi,
                endpoints_file=endpoints_file,
                crawl=crawl,
            )
            
            # Add known endpoints
            if known_endpoints:
                console.print(f"[dim]Adding {len(known_endpoints)} known bounty endpoints[/dim]")
                endpoints.extend(known_endpoints)
            
            progress.update(
                discover_task,
                description=f"[green]✓ Discovered {len(endpoints)} endpoints[/green]"
            )
        
        # Run IDOR detection
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            scan_task = progress.add_task("Scanning for vulnerabilities...", total=None)
            
            detector = IDORDetector(http_client, session_manager, config)
            result = await detector.scan(discovery, sessions)
            
            vuln_count = len(result.vulnerabilities)
            if vuln_count > 0:
                progress.update(
                    scan_task,
                    description=f"[red]⚠ Found {vuln_count} vulnerabilities![/red]"
                )
            else:
                progress.update(
                    scan_task,
                    description="[green]✓ Scan complete - no vulnerabilities found[/green]"
                )
        
        console.print()
        return result


@app.command()
def discover(
    target: str = typer.Argument(..., help="Target API base URL"),
    openapi: Optional[str] = typer.Option(
        None, "--openapi", "-o",
        help="Path or URL to OpenAPI/Swagger spec"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-O",
        help="Output file for discovered endpoints"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable verbose output"
    ),
) -> None:
    """
    🔎 Discover API endpoints without scanning.
    
    Useful for reconnaissance and creating endpoint lists for later scanning.
    """
    setup_logging(verbose)
    
    console.print()
    console.print(f"[bold blue]Discovering endpoints for:[/bold blue] {target}")
    console.print()
    
    async def _discover():
        async with HTTPClient() as http_client:
            discovery = EndpointDiscovery(http_client, target)
            return await discovery.discover_all(
                openapi_path=openapi,
                crawl=True,
            )
    
    try:
        endpoints = asyncio.run(_discover())
    except Exception as e:
        console.print(f"[red]Discovery failed: {e}[/red]")
        raise typer.Exit(1)
    
    # Display results
    console.print(f"[green]Found {len(endpoints)} endpoints:[/green]")
    console.print()
    
    for ep in endpoints:
        has_ids = "🎯" if ep.resource_ids else "  "
        console.print(f"  {has_ids} {ep.method.value:6} {ep.path}")
    
    # Save to file
    if output:
        with open(output, "w") as f:
            for ep in endpoints:
                f.write(f"{ep.method.value} {ep.path}\n")
        console.print()
        console.print(f"[green]✓ Saved to {output}[/green]")
    
    console.print()
    testable = sum(1 for ep in endpoints if ep.resource_ids)
    console.print(f"[dim]🎯 = Testable for IDOR ({testable} endpoints have resource IDs)[/dim]")


@app.command()
def version() -> None:
    """Show version information."""
    console.print()
    console.print(
        Panel(
            f"[bold blue]IDOR Scanner[/bold blue]\n"
            f"Version: {__version__}\n"
            f"Python: {sys.version.split()[0]}",
            border_style="blue",
        )
    )


@app.command(name="bounty-list")
def bounty_list() -> None:
    """
    📋 List available bug bounty program presets.
    
    Shows pre-configured settings for popular bug bounty programs.
    """
    from rich.table import Table
    
    console.print()
    console.print("[bold blue]Available Bug Bounty Presets[/bold blue]")
    console.print()
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Name", style="cyan")
    table.add_column("Platform")
    table.add_column("Rate Limit")
    table.add_column("UA Suffix")
    table.add_column("Domains")
    
    from .bounty_mode import BOUNTY_PROGRAMS
    
    for key, config in BOUNTY_PROGRAMS.items():
        domains = ", ".join(config.in_scope_domains[:2])
        if len(config.in_scope_domains) > 2:
            domains += f"... (+{len(config.in_scope_domains) - 2})"
        
        table.add_row(
            key,
            config.platform,
            f"{config.rate_limit}/s",
            config.user_agent_suffix or "-",
            domains,
        )
    
    console.print(table)
    console.print()
    console.print("[dim]Usage: idor-scanner scan ... --bounty inditex[/dim]")


if __name__ == "__main__":
    app()
