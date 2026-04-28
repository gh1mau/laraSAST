import subprocess
import json
import os

class SemgrepWrapper:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "OWASP/Semgrep Engine"

    def scan(self):
        # We target common OWASP categories using Semgrep's curated Laravel rules
        cmd = [
            "semgrep",
            "--config", "p/laravel",
            "--config", "p/owasp-top-10",
            "--json",
            self.project_path
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if not result.stdout: return []
            
            data = json.loads(result.stdout)
            findings = []
            for item in data.get('results', []):
                findings.append({
                    "module": self.module_name,
                    "issue": item['extra']['message'],
                    "severity": item['extra']['severity'],
                    "file": item['path']
                })
            return findings
        except Exception:
            return []
