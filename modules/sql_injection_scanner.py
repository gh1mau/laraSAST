import os
import glob
import re

class SqlInjectionScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "SQL Injection Analysis"

    def scan(self):
        findings = []
        # Scan controllers and models
        files = glob.glob(f"{self.project_path}/app/**/*.php", recursive=True)

        for file_path in files:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                # Detect DB::raw, whereRaw, etc with variable concatenation
                if re.search(r"(raw|whereRaw|orderByRaw|havingRaw)\(.*\$.*\)", content):
                    if "sprintf" not in content: # Simple heuristic to avoid some false positives
                        findings.append({
                            "module": self.module_name,
                            "issue": "Potential SQL Injection: Raw query with dynamic variable detected",
                            "severity": "CRITICAL",
                            "file": file_path
                        })
        return findings