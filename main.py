import argparse
import sys
import os
import shutil
import subprocess
import getpass
from core.engine import ScannerEngine
from rich.console import Console
from rich.panel import Panel

console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner_text = r"""
 ██╗      █████╗ ██████╗  █████╗ ███████╗ █████╗ ███████╗████████╗
 ██║     ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝
 ██║     ███████║██████╔╝███████║███████╗███████║███████╗   ██║   
 ██║     ██╔══██║██╔══██╗██╔══██║╚════██║██╔══██║╚════██║   ██║   
 ███████╗██║  ██║██║  ██║██║  ██║███████║██║  ██║███████║   ██║   
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   

           [bold white]Laravel Static Analysis Security Tool[/bold white]
           [bold yellow]Author: Hussein bin Mohamed | masta ghimau[/bold yellow]
    """
    console.print(Panel(banner_text.strip("\n"), border_style="bold blue", expand=False, padding=(1, 2)))

def check_dependencies():
    """Verify if external security tools are installed."""
    deps = {
        "semgrep": "Semgrep Engine",
        "composer": "PHP Composer (Dependency Audit)",
        "nuclei": "Nuclei Engine",
        "grype": "Grype (Vulnerability Scanner)",
        "syft": "Syft (SBOM Generator)"
    }
    
    missing = []
    for cmd, name in deps.items():
        if not shutil.which(cmd):
            missing.append(f"[bold yellow]- {name} ({cmd})[/bold yellow]")
    
    if missing:
        console.print("[bold red]![/bold red] [bold white]Warning: Some dependencies are missing. Results might be incomplete:[/bold white]")
        for m in missing:
            console.print(m)
        console.print("")

    # Update grype database if installed
    if shutil.which("grype"):
        with console.status("[bold green]Updating Grype vulnerability database...", spinner="dots"):
            try:
                subprocess.run(["grype", "db", "update"], capture_output=True, check=True)
                console.print("[bold green]✓[/bold green] Grype database updated.")
            except Exception:
                console.print("[bold yellow]![/bold yellow] Failed to update Grype database. Continuing with local version.")

def main():
    if not ("--format" in sys.argv and "json" in sys.argv):
        clear_screen()
        print_banner()
        check_dependencies()

    parser = argparse.ArgumentParser(description="LaraSAST: High-Performance SAST for Laravel/MySQL")
    parser.add_argument("path", help="Path to the Laravel project directory")
    parser.add_argument("--format", choices=['json', 'text', 'html'], default='text', help="Output format (default: text)")
    parser.add_argument("--severity", choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ALL'], default='LOW', help="Minimum severity to report")
    parser.add_argument("--ai", action="store_true", help="Use AI (Gemini) to analyze findings for PoC and mitigation")
    parser.add_argument("--ai-model", default="mistralai/mistral-7b-instruct-v0.2", help="Specify the OpenRouter model to use (default: mistralai/mistral-7b-instruct-v0.2)")
    parser.add_argument("--list-models", action="store_true", help="List available models from OpenRouter")

    args = parser.parse_args()
    
    api_key = os.getenv("OPENROUTER_API_KEY")

    # Handle listing models
    if args.list_models:
        if not api_key:
            api_key = getpass.getpass("  Enter OpenRouter API Key (input hidden): ").strip()
        if api_key:
            from core.ai_analyzer import AIAnalyzer
            analyzer = AIAnalyzer(console, api_key)
            analyzer.list_models()
        sys.exit(0)

    # If AI is enabled and API key is not found, prompt the user
    if args.ai and not api_key:
        console.print("[bold yellow]![/bold yellow] OpenRouter API Key not found in environment.")
        api_key = getpass.getpass("  Enter OpenRouter API Key (input hidden): ").strip()
        if not api_key:
            console.print("[bold red]Error:[/bold red] API Key is required for AI analysis when --ai is enabled.")
            sys.exit(1)

    try:
        engine = ScannerEngine(args.path, args.severity, console, use_ai=args.ai, api_key=api_key, ai_model=args.ai_model)
        results = engine.run_all_scans()
        engine.generate_report(results, args.format)
    except Exception as e:
        console.print(f"[bold red]CRITICAL ERROR:[/bold red] [red]{str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
