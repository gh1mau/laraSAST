import os
import glob
import re

class XssScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "XSS Analysis (Blade)"

    def scan(self):
        findings = []
        # Scan all blade templates
        files = glob.glob(f"{self.project_path}/resources/views/**/*.blade.php", recursive=True)

        for file_path in files:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                # Detect unescaped output {!! $var !!}
                if re.search(r"\{!!\s*.*\s*!!\}", content):
                    findings.append({
                        "module": self.module_name,
                        "issue": "Unescaped output detected in Blade (Potential XSS)",
                        "severity": "HIGH",
                        "file": file_path,
                        "remediation": "Use {{ $var }} for automatic escaping. Use {!! !!} only for trusted HTML content."
                    })
        return findings