import json
from datetime import datetime
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.columns import Columns

class Reporter:
    def __init__(self, findings, project_path="N/A"):
        self.findings = findings
        self.project_path = project_path
        self.console = Console()

    def to_console(self):
        if not self.findings:
            self.console.print("[bold green]No vulnerabilities found![/bold green]")
            return

        # Header Section
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header_info = f"[bold cyan]Project Path:[/bold cyan] {self.project_path}\n[bold cyan]Scan Time:[/bold cyan] {scan_time}\n[bold cyan]Total Findings:[/bold cyan] {len(self.findings)}"
        self.console.print(Panel(header_info, title="[bold white]LaraSAST Scan Details[/bold white]", border_style="blue"))

        # Group findings by module
        grouped_findings = {}
        for f in self.findings:
            module = f.get('module', 'Other Analysis')
            if module not in grouped_findings:
                grouped_findings[module] = []
            grouped_findings[module].append(f)

        # Stats for final summary
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        severity_styles = {
            "CRITICAL": "bold red",
            "HIGH": "bold bright_red",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue",
            "INFO": "bold cyan",
            "ERROR": "bold red"
        }
        severity_icons = {
            "CRITICAL": "💀",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "ℹ️"
        }

        global_idx = 1
        for module_name, findings in grouped_findings.items():
            table = Table(title=f"📦 [bold white]Module: {module_name}[/bold white]", show_lines=True, header_style="bold magenta", expand=True)
            table.add_column("ID", style="dim", width=5)
            table.add_column("Severity", justify="left", width=15)
            table.add_column("Issue & Remediation")
            table.add_column("Location", ratio=1)

            for f in findings:
                severity = str(f.get('severity', 'INFO')).upper()
                style = severity_styles.get(severity, "white")
                icon = severity_icons.get(severity, "❓")
                stats[severity if severity in stats else "INFO"] += 1
                
                issue_text = f"[bold white]{f.get('issue', 'N/A')}[/bold white]"
                remediation = f.get('remediation', 'Follow Laravel security best practices.')
                combined_issue = f"{issue_text}\n[dim italic green]💡 Remediation: {remediation}[/dim italic green]"

                table.add_row(
                    str(global_idx),
                    f"{icon} [{style}]{severity}[/{style}]",
                    combined_issue,
                    f.get('file', 'N/A')
                )
                global_idx += 1
            
            self.console.print(table)
            self.console.print("")

        # Final Summary Panel
        summary_text = (
            f"[bold red]Critical: {stats['CRITICAL']}[/bold red]  |  "
            f"[bold bright_red]High: {stats['HIGH']}[/bold bright_red]  |  "
            f"[bold yellow]Medium: {stats['MEDIUM']}[/bold yellow]  |  "
            f"[bold blue]Low: {stats['LOW']}[/bold blue]  |  "
            f"[bold cyan]Info: {stats['INFO']}[/bold cyan]"
        )
        self.console.print(Panel(summary_text, title="Final Vulnerability Count", border_style="bold green"))

    def to_json(self):
        self.console.print_json(data=self.findings)

    def to_html(self):
        """Generates a professional-grade HTML report with charts (Acunetix style)."""
        now = datetime.now()
        scan_time = now.strftime("%Y-%m-%d %H:%M:%S")
        file_timestamp = now.strftime("%Y%m%d_%H%M%S")
        output_file = f"larasast-report_{file_timestamp}.html"
        
        # Calculate Statistics
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        module_stats = {}
        for f in self.findings:
            sev = str(f.get('severity', 'INFO')).upper()
            if sev in stats: stats[sev] += 1
            
            mod = f.get('module', 'Other')
            module_stats[mod] = module_stats.get(mod, 0) + 1

        # Group findings for the table
        grouped = {}
        for f in self.findings:
            mod = f.get('module', 'Other')
            if mod not in grouped: grouped[mod] = []
            grouped[mod].append(f)

        # Generate Navigation Links
        nav_links = ""
        for module in grouped.keys():
            safe_id = module.lower().replace(" ", "-").replace("(", "").replace(")", "")
            nav_links += f'<a href="#{safe_id}" class="block px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 hover:text-blue-600 rounded-lg transition-colors truncate">{module}</a>\n'

        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LaraSAST Security Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
        body {{ font-family: 'Inter', sans-serif; background-color: #f8fafc; }}
        .severity-CRITICAL {{ border-left: 6px solid #dc2626; }}
        .severity-HIGH {{ border-left: 6px solid #ea580c; }}
        .severity-MEDIUM {{ border-left: 6px solid #ca8a04; }}
        .severity-LOW {{ border-left: 6px solid #2563eb; }}
    </style>
</head>
<body class="p-8">
    <div class="max-w-7xl mx-auto flex flex-col lg:flex-row gap-8">
        <!-- Sidebar Navigation -->
        <aside class="w-full lg:w-64 shrink-0">
            <div class="lg:sticky lg:top-8 bg-white p-5 rounded-xl shadow-sm border border-slate-200">
                <h3 class="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">Modules</h3>
                <nav class="space-y-1">
                    {nav_links}
                </nav>
            </div>
        </aside>

        <!-- Main Content -->
        <div class="flex-1 min-w-0">
            <!-- Header -->
            <div class="flex justify-between items-center mb-8 bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                <div>
                    <h1 class="text-3xl font-bold text-slate-900">LaraSAST <span class="text-blue-600">Audit Report</span></h1>
                    <p class="text-slate-500 mt-1">Author: Hussein bin Mohamed | masta ghimau</p>
                </div>
                <div class="text-right">
                    <p class="text-sm font-semibold text-slate-400 uppercase tracking-wider">Scan Date</p>
                    <p class="text-lg font-bold text-slate-700">{scan_time}</p>
                </div>
            </div>

            <!-- Summary Dashboard -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                    <p class="text-slate-500 text-sm font-medium">Total Findings</p>
                    <p class="text-4xl font-bold text-slate-900">{len(self.findings)}</p>
                </div>
                <div class="bg-red-50 p-6 rounded-xl border border-red-100">
                    <p class="text-red-600 text-sm font-medium">Critical Issues</p>
                    <p class="text-4xl font-bold text-red-700">{stats['CRITICAL']}</p>
                </div>
                <div class="bg-orange-50 p-6 rounded-xl border border-orange-100">
                    <p class="text-orange-600 text-sm font-medium">High Risk</p>
                    <p class="text-4xl font-bold text-orange-700">{stats['HIGH']}</p>
                </div>
                <div class="bg-blue-50 p-6 rounded-xl border border-blue-100">
                    <p class="text-blue-600 text-sm font-medium">Project Path</p>
                    <p class="text-xs truncate font-mono mt-2 text-blue-800">{self.project_path}</p>
                </div>
            </div>

            <!-- Charts Section -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
                <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                    <h3 class="text-lg font-bold mb-4 text-slate-800">Severity Distribution</h3>
                    <canvas id="severityChart" height="200"></canvas>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
                    <h3 class="text-lg font-bold mb-4 text-slate-800">Findings by Module</h3>
                    <canvas id="moduleChart" height="200"></canvas>
                </div>
            </div>

            <!-- Detailed Findings -->
            <h2 class="text-2xl font-bold mb-6 text-slate-900">Detailed Findings</h2>
        """
        
        for module, findings in grouped.items():
            safe_id = module.lower().replace(" ", "-").replace("(", "").replace(")", "")
            html_template += f"""
            <div class="mb-10" id="{safe_id}">
                <h3 class="text-xl font-semibold mb-4 text-slate-700 flex items-center">
                    <span class="bg-slate-200 text-slate-700 px-3 py-1 rounded-lg text-sm mr-3 uppercase">{module}</span>
                </h3>
                <div class="space-y-4">
            """
            for f in findings:
                sev = f.get('severity', 'INFO').upper()
                html_template += f"""
                    <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200 severity-{sev}">
                        <div class="flex justify-between items-start mb-2">
                            <h4 class="text-lg font-bold text-slate-800">{f.get('issue')}</h4>
                            <span class="px-3 py-1 rounded-full text-xs font-bold severity-bg-{sev} uppercase tracking-tighter">
                                {sev}
                            </span>
                        </div>
                        <p class="text-slate-600 mb-4 text-sm font-mono bg-slate-50 p-2 rounded border border-slate-100">
                            {f.get('file')}
                        </p>
                        
                        {"".join([f'''
                        <div class="bg-purple-50 p-4 rounded-lg border border-purple-100 mb-4">
                            <div class="mb-3">
                                <span class="text-purple-900 font-bold text-xs uppercase tracking-wider italic">🧪 AI Generated PoC</span>
                                <p class="text-purple-800 text-sm mt-1">{f.get('ai_poc')}</p>
                            </div>
                            <div>
                                <span class="text-indigo-900 font-bold text-xs uppercase tracking-wider italic">🛡️ AI Mitigation Advice</span>
                                <p class="text-indigo-800 text-sm mt-1">{f.get('ai_mitigation')}</p>
                            </div>
                        </div>''' if f.get('ai_poc') else ""])}

                        <div class="bg-emerald-50 p-4 rounded-lg border border-emerald-100">
                            <p class="text-emerald-800 text-sm">
                                <span class="font-bold">💡 Remediation:</span> {f.get('remediation', 'Follow standard Laravel security guidelines to patch this issue.')}
                            </p>
                        </div>
                    </div>
                """
            html_template += "</div></div>"

        html_template += f"""
    </div>

    <script>
        // Severity Colors
        const colors = {{
            CRITICAL: '#dc2626',
            HIGH: '#ea580c',
            MEDIUM: '#ca8a04',
            LOW: '#2563eb',
            INFO: '#64748b'
        }};

        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{stats['CRITICAL']}, {stats['HIGH']}, {stats['MEDIUM']}, {stats['LOW']}, {stats['INFO']}],
                    backgroundColor: [colors.CRITICAL, colors.HIGH, colors.MEDIUM, colors.LOW, colors.INFO]
                }}]
            }},
            options: {{ responsive: true, plugins: {{ legend: {{ position: 'right' }} }} }}
        }});

        // Module Chart
        new Chart(document.getElementById('moduleChart'), {{
            type: 'bar',
            data: {{
                labels: {list(module_stats.keys())},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {list(module_stats.values())},
                    backgroundColor: '#3b82f6'
                }}]
            }},
            options: {{ 
                responsive: true, 
                indexAxis: 'y',
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});
    </script>
    
    <style>
        .severity-bg-CRITICAL {{ background-color: #fee2e2; color: #991b1b; }}
        .severity-bg-HIGH {{ background-color: #ffedd5; color: #9a3412; }}
        .severity-bg-MEDIUM {{ background-color: #fef9c3; color: #854d0e; }}
        .severity-bg-LOW {{ background-color: #dbeafe; color: #1e40af; }}
        .severity-bg-INFO {{ background-color: #f1f5f9; color: #475569; }}
    </style>
</body>
</html>
        """
        
        with open(output_file, "w", encoding="utf-8") as hf:
            hf.write(html_template)
        
        self.console.print(f"\n[bold green]✅ Success![/bold green] HTML report generated: [bold white]{output_file}[/bold white]")
