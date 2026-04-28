import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.env_scanner import EnvScanner
from modules.route_scanner import RouteScanner
from modules.upload_scanner import UploadScanner
from modules.idor_scanner import IdorScanner
from modules.dependency_checker import DependencyChecker
from modules.semgrep_wrapper import SemgrepWrapper
from modules.nuclei_wrapper import NucleiWrapper
from modules.secret_scanner import SecretScanner
from modules.exposure_scanner import ExposureScanner
from modules.logic_scanner import LogicScanner
from modules.config_hardening_scanner import ConfigHardeningScanner
from modules.xss_scanner import XssScanner
from modules.mass_assignment_scanner import MassAssignmentScanner
from modules.sql_injection_scanner import SqlInjectionScanner
from modules.csrf_scanner import CsrfScanner
from modules.version_scanner import VersionScanner
from core.reporter import Reporter
from core.ai_analyzer import AIAnalyzer

class ScannerEngine:
    def __init__(self, project_path, min_severity, console, use_ai=False, api_key=None, ai_model="mistralai/mistral-7b-instruct-v0.2"):
        self.project_path = os.path.abspath(project_path)
        self.min_severity = min_severity
        self.console = console
        self.use_ai = use_ai
        self.api_key = api_key
        self.ai_model = ai_model
        self.scanners = [
            EnvScanner(self.project_path),
            RouteScanner(self.project_path),
            UploadScanner(self.project_path),
            IdorScanner(self.project_path),
            DependencyChecker(self.project_path),
            SemgrepWrapper(self.project_path),
            NucleiWrapper(self.project_path),
            SecretScanner(self.project_path),
            ExposureScanner(self.project_path),
            LogicScanner(self.project_path),
            ConfigHardeningScanner(self.project_path),
            XssScanner(self.project_path),
            MassAssignmentScanner(self.project_path),
            SqlInjectionScanner(self.project_path),
            CsrfScanner(self.project_path),
            VersionScanner(self.project_path)
        ]

    def run_all_scans(self):
        """Run all scanners and filter findings by severity."""
        all_findings = []
        severity_map = {"ALL": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "ERROR": 4}
        min_val = severity_map.get(self.min_severity.upper(), 1)

        with self.console.status("[bold green]Initializing LaraSAST Engine...", spinner="dots") as status:
            with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
                # Submit all scanning tasks
                future_to_scanner = {executor.submit(scanner.scan): scanner for scanner in self.scanners}
                
                for future in as_completed(future_to_scanner):
                    scanner = future_to_scanner[future]
                    status.update(f"[bold green]Processing {scanner.module_name}...")
                    try:
                        findings = future.result()
                        if findings:
                            for f in findings:
                                sev = f.get('severity', 'LOW').upper()
                                if severity_map.get(sev, 1) >= min_val:
                                    all_findings.append(f)
                    except Exception as e:
                        all_findings.append({"module": scanner.module_name, "issue": f"Scanner Error: {str(e)}", "severity": "INFO"})
        
        # Run AI Analysis if requested and findings exist
        if self.use_ai and all_findings:
            ai_analyzer = AIAnalyzer(self.console, self.api_key, self.ai_model)
            all_findings = ai_analyzer.analyze(all_findings)

        # Sort findings: Group by Module (A-Z) and then Severity (Critical -> Info)
        all_findings.sort(
            key=lambda x: (x.get('module', ''), -severity_map.get(x.get('severity', 'INFO').upper(), 0))
        )

        return all_findings

    def generate_report(self, findings, format):
        reporter = Reporter(findings, self.project_path)
        if format == 'json':
            reporter.to_json()
        elif format == 'html':
            reporter.to_html()
        else:
            reporter.to_console()
