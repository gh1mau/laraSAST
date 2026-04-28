import os
import re
import glob

class SecretScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Secret Scanner"
        # Common API Key patterns
        self.patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Generic Secret": r"(?i)(key|secret|password|auth|token|access)\s*[:=>]+\s*['\"]([a-zA-Z0-9\-_]{16,})['\"]",
            "Google API": r"AIza[0-9A-Za-z-_]{35}"
        }

    def scan(self):
        findings = []
        # Scan all php and env files
        files = glob.glob(f"{self.project_path}/**/*.php", recursive=True)
        files.extend(glob.glob(f"{self.project_path}/.env*"))

        for file_path in files:
            if "vendor" in file_path: continue
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                for name, pattern in self.patterns.items():
                    if re.search(pattern, content):
                        findings.append({
                            "module": self.module_name,
                            "issue": f"Potential {name} hardcoded",
                            "severity": "CRITICAL",
                            "file": file_path
                        })
        return findings