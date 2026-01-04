"""
Report Generator for the IDOR Scanner.

Generates professional vulnerability reports in multiple formats:
- Terminal (Rich formatted)
- JSON (for automation)
- Markdown (for bug bounties)
- HTML (for professional reports)
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import ScanResult, Severity, Vulnerability

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates professional vulnerability reports.
    
    Supports multiple output formats:
    - Terminal: Rich formatted output with colors and tables
    - JSON: Machine-readable for CI/CD integration
    - Markdown: For bug bounty submissions
    - HTML: Professional client-ready reports
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir) if output_dir else Path("./reports")
        self.console = Console()
    
    def generate_terminal(self, result: ScanResult) -> None:
        """Generate beautiful terminal output using Rich."""
        
        # Header
        self.console.print()
        self.console.print(
            Panel(
                "[bold white]API ACCESS CONTROL SCAN REPORT[/bold white]",
                border_style="blue",
            )
        )
        
        # Summary table
        summary_table = Table(
            title="📊 Scan Summary",
            show_header=True,
            header_style="bold cyan",
        )
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Target", result.target)
        summary_table.add_row("Scan ID", result.scan_id)
        summary_table.add_row(
            "Duration", 
            f"{result.duration:.1f}s" if result.duration else "N/A"
        )
        summary_table.add_row("Endpoints Scanned", str(result.endpoints_scanned))
        summary_table.add_row("", "")
        
        # Severity counts with colors
        total_vulns = len(result.vulnerabilities)
        if total_vulns == 0:
            summary_table.add_row("Vulnerabilities", "[bold green]0[/bold green]")
        else:
            summary_table.add_row(
                "Total Vulnerabilities", 
                f"[bold red]{total_vulns}[/bold red]"
            )
            
            critical = result.count_by_severity(Severity.CRITICAL)
            high = result.count_by_severity(Severity.HIGH)
            medium = result.count_by_severity(Severity.MEDIUM)
            low = result.count_by_severity(Severity.LOW)
            
            if critical > 0:
                summary_table.add_row(
                    "  Critical", 
                    f"[bold red on white] {critical} [/bold red on white]"
                )
            if high > 0:
                summary_table.add_row("  High", f"[red]{high}[/red]")
            if medium > 0:
                summary_table.add_row("  Medium", f"[yellow]{medium}[/yellow]")
            if low > 0:
                summary_table.add_row("  Low", f"[green]{low}[/green]")
        
        self.console.print(summary_table)
        self.console.print()
        
        # Vulnerabilities
        if result.vulnerabilities:
            self.console.print("[bold red]🚨 VULNERABILITIES FOUND[/bold red]")
            self.console.print()
            
            for i, vuln in enumerate(result.vulnerabilities, 1):
                self._print_vulnerability(i, vuln)
        else:
            self.console.print(
                Panel(
                    "[bold green]✅ No vulnerabilities found![/bold green]\n"
                    "All tested endpoints have proper access controls.",
                    border_style="green",
                )
            )
        
        self.console.print()
        self.console.print("─" * 70, style="dim")
        self.console.print(f"[dim]Report generated at {datetime.now().isoformat()}[/dim]")
        self.console.print()
    
    def _print_vulnerability(self, index: int, vuln: Vulnerability) -> None:
        """Print a single vulnerability to terminal."""
        
        severity_styles = {
            Severity.CRITICAL: "bold white on red",
            Severity.HIGH: "bold red",
            Severity.MEDIUM: "bold yellow",
            Severity.LOW: "green",
            Severity.INFO: "dim",
        }
        
        style = severity_styles.get(vuln.severity, "white")
        
        # Title
        self.console.print(
            f"[{style}]#{index} [{vuln.severity.value}] {vuln.title}[/{style}]"
        )
        
        # Details
        self.console.print(f"   [dim]Endpoint:[/dim] {vuln.method.value} {vuln.endpoint}")
        self.console.print(f"   [dim]Type:[/dim] {vuln.vuln_type}")
        self.console.print(f"   [dim]Description:[/dim] {vuln.description}")
        
        # Sensitive fields
        if vuln.evidence.sensitive_fields_exposed:
            fields = ", ".join(vuln.evidence.sensitive_fields_exposed[:5])
            self.console.print(f"   [dim]Sensitive Fields:[/dim] [red]{fields}[/red]")
        
        # Impact
        self.console.print(f"   [dim]Impact:[/dim] {vuln.impact[:100]}...")
        
        self.console.print()
    
    def generate_json(self, result: ScanResult) -> str:
        """Generate JSON report for automation/CI integration."""
        
        report = {
            "scan_info": {
                "scan_id": result.scan_id,
                "target": result.target,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration_seconds": result.duration,
                "scanner_version": "1.0.0",
            },
            "summary": {
                "endpoints_discovered": result.endpoints_discovered,
                "endpoints_scanned": result.endpoints_scanned,
                "total_vulnerabilities": len(result.vulnerabilities),
                "by_severity": {
                    "critical": result.count_by_severity(Severity.CRITICAL),
                    "high": result.count_by_severity(Severity.HIGH),
                    "medium": result.count_by_severity(Severity.MEDIUM),
                    "low": result.count_by_severity(Severity.LOW),
                },
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "type": v.vuln_type,
                    "endpoint": v.endpoint,
                    "method": v.method.value,
                    "description": v.description,
                    "impact": v.impact,
                    "victim_user": v.victim_user,
                    "attacker_user": v.attacker_user,
                    "cwe": v.cwe,
                    "cvss_score": v.cvss_score,
                    "evidence": {
                        "baseline_request": v.evidence.baseline_request,
                        "attack_request": v.evidence.attack_request,
                        "sensitive_fields": v.evidence.sensitive_fields_exposed,
                    },
                    "remediation": v.remediation,
                }
                for v in result.vulnerabilities
            ],
            "status": result.status,
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_markdown(self, result: ScanResult) -> str:
        """Generate Markdown report for bug bounty submissions."""
        
        lines = [
            "# API Security Scan Report",
            "",
            f"**Target:** `{result.target}`  ",
            f"**Scan ID:** {result.scan_id}  ",
            f"**Date:** {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Duration:** {result.duration:.1f}s  " if result.duration else "",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Endpoints Scanned | {result.endpoints_scanned} |",
            f"| Total Vulnerabilities | {len(result.vulnerabilities)} |",
            f"| Critical | {result.count_by_severity(Severity.CRITICAL)} |",
            f"| High | {result.count_by_severity(Severity.HIGH)} |",
            f"| Medium | {result.count_by_severity(Severity.MEDIUM)} |",
            f"| Low | {result.count_by_severity(Severity.LOW)} |",
            "",
        ]
        
        if result.vulnerabilities:
            lines.extend([
                "---",
                "",
                "## Vulnerability Details",
                "",
            ])
            
            for vuln in result.vulnerabilities:
                lines.extend(self._vulnerability_to_markdown(vuln))
        else:
            lines.extend([
                "---",
                "",
                "## Result",
                "",
                "✅ **No vulnerabilities found!**",
                "",
                "All tested endpoints implement proper access controls.",
            ])
        
        return "\n".join(lines)
    
    def _vulnerability_to_markdown(self, vuln: Vulnerability) -> list:
        """Convert a vulnerability to Markdown format."""
        
        severity_badge = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH: "🟠 HIGH",
            Severity.MEDIUM: "🟡 MEDIUM",
            Severity.LOW: "🟢 LOW",
        }
        
        lines = [
            f"### {severity_badge.get(vuln.severity, vuln.severity.value)}: {vuln.title}",
            "",
            f"**Endpoint:** `{vuln.method.value} {vuln.endpoint}`  ",
            f"**Vulnerability Type:** {vuln.vuln_type}  ",
            f"**CWE:** {vuln.cwe}  ",
            f"**CVSS Score:** {vuln.cvss_score}  ",
            "",
            "#### Description",
            "",
            vuln.description,
            "",
            "#### Impact",
            "",
            vuln.impact,
            "",
            "#### Proof of Concept",
            "",
            "**Step 1:** Authenticate as victim user",
            f"```",
            f"User: {vuln.victim_user}",
            f"```",
            "",
            "**Step 2:** Victim accesses their resource",
            f"```http",
            f"{vuln.evidence.baseline_request.get('method', 'GET')} {vuln.evidence.baseline_request.get('url', vuln.endpoint)}",
            f"```",
            "",
            "**Step 3:** Attacker accesses victim's resource",
            f"```http",
            f"{vuln.evidence.attack_request.get('method', 'GET')} {vuln.evidence.attack_request.get('url', vuln.endpoint)}",
            f"Authorization: Bearer [attacker_token]",
            f"```",
            "",
        ]
        
        if vuln.evidence.sensitive_fields_exposed:
            lines.extend([
                "**Sensitive Fields Exposed:**",
                "",
                "```",
                ", ".join(vuln.evidence.sensitive_fields_exposed),
                "```",
                "",
            ])
        
        lines.extend([
            "#### Remediation",
            "",
            "```python",
            vuln.remediation,
            "```",
            "",
            "#### References",
            "",
            f"- OWASP API Security Top 10: {vuln.owasp_ref}",
            f"- {vuln.cwe}",
            "",
            "---",
            "",
        ])
        
        return lines
    
    def generate_html(self, result: ScanResult) -> str:
        """Generate HTML report with professional styling."""
        
        # Generate markdown first, then convert
        markdown_content = self.generate_markdown(result)
        
        # Simple markdown to HTML (for full conversion, use a library)
        html_body = self._simple_markdown_to_html(markdown_content)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Scan Report - {result.scan_id}</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --text-color: #c9d1d9;
            --heading-color: #ffffff;
            --border-color: #30363d;
            --code-bg: #161b22;
            --critical: #ff4757;
            --high: #ff6348;
            --medium: #ffa502;
            --low: #2ed573;
            --accent: #58a6ff;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        
        h1 {{
            color: var(--heading-color);
            border-bottom: 2px solid var(--accent);
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
        }}
        
        h2 {{
            color: var(--heading-color);
            margin-top: 2rem;
            margin-bottom: 1rem;
        }}
        
        h3 {{
            color: var(--heading-color);
            margin-top: 1.5rem;
            margin-bottom: 0.5rem;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}
        
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border: 1px solid var(--border-color);
        }}
        
        th {{
            background-color: var(--code-bg);
        }}
        
        code {{
            background-color: var(--code-bg);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: 'Fira Code', Consolas, monospace;
        }}
        
        pre {{
            background-color: var(--code-bg);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            margin: 1rem 0;
        }}
        
        pre code {{
            padding: 0;
        }}
        
        .severity-critical {{
            color: var(--critical);
            font-weight: bold;
        }}
        
        .severity-high {{
            color: var(--high);
            font-weight: bold;
        }}
        
        .severity-medium {{
            color: var(--medium);
        }}
        
        .severity-low {{
            color: var(--low);
        }}
        
        hr {{
            border: none;
            border-top: 1px solid var(--border-color);
            margin: 2rem 0;
        }}
        
        .vuln-card {{
            background: var(--code-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
        }}
        
        .success {{
            color: var(--low);
            font-size: 1.2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        {html_body}
    </div>
</body>
</html>"""
        
        return html
    
    def _simple_markdown_to_html(self, markdown: str) -> str:
        """Simple markdown to HTML conversion."""
        import re
        
        html = markdown
        
        # Headers
        html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        
        # Bold
        html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
        
        # Code blocks
        html = re.sub(
            r'```(\w+)?\n(.*?)```',
            r'<pre><code>\2</code></pre>',
            html,
            flags=re.DOTALL
        )
        
        # Inline code
        html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
        
        # Tables (basic)
        lines = html.split('\n')
        in_table = False
        new_lines = []
        
        for line in lines:
            if line.startswith('|') and '|' in line[1:]:
                if not in_table:
                    new_lines.append('<table>')
                    in_table = True
                
                if '---' in line:
                    continue  # Skip separator
                
                cells = [c.strip() for c in line.split('|')[1:-1]]
                row = '<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>'
                new_lines.append(row)
            else:
                if in_table:
                    new_lines.append('</table>')
                    in_table = False
                new_lines.append(line)
        
        if in_table:
            new_lines.append('</table>')
        
        html = '\n'.join(new_lines)
        
        # Horizontal rules
        html = html.replace('---', '<hr>')
        
        # Line breaks
        html = re.sub(r'  $', '<br>', html, flags=re.MULTILINE)
        
        # Paragraphs
        html = re.sub(r'\n\n+', '</p><p>', html)
        html = '<p>' + html + '</p>'
        
        return html
    
    def save_reports(self, result: ScanResult, formats: list = None) -> dict:
        """Save reports in specified formats."""
        
        if formats is None:
            formats = ["json", "markdown", "html"]
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved = {}
        
        if "json" in formats:
            path = self.output_dir / f"scan_{result.scan_id}_{timestamp}.json"
            path.write_text(self.generate_json(result))
            saved["json"] = str(path)
            logger.info(f"Saved JSON report: {path}")
        
        if "markdown" in formats:
            path = self.output_dir / f"scan_{result.scan_id}_{timestamp}.md"
            path.write_text(self.generate_markdown(result))
            saved["markdown"] = str(path)
            logger.info(f"Saved Markdown report: {path}")
        
        if "html" in formats:
            path = self.output_dir / f"scan_{result.scan_id}_{timestamp}.html"
            path.write_text(self.generate_html(result))
            saved["html"] = str(path)
            logger.info(f"Saved HTML report: {path}")
        
        return saved
