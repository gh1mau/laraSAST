import os
import glob
import re

class IdorScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "IDOR Analysis"

    def scan(self):
        findings = []
        controllers = glob.glob(f"{self.project_path}/app/Http/Controllers/**/*.php", recursive=True)

        for controller in controllers:
            with open(controller, 'r') as f:
                content = f.read()
                # Look for direct model access in Update/Delete methods
                if re.search(r"(update|delete|destroy|edit)\(.*\$.*\)", content):
                    if not any(x in content for x in ["authorize", "Gate::", "Policy", "can("]):
                        findings.append({
                            "module": self.module_name,
                            "issue": "Possible IDOR: Sensitive action without explicit authorization check",
                            "severity": "HIGH",
                            "file": controller
                        })
        return findings
