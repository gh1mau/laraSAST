import os
import glob
import re

class RouteScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Route Analysis"

    def scan(self):
        findings = []
        route_files = glob.glob(f"{self.project_path}/routes/*.php")
        
        for rf in route_files:
            with open(rf, 'r') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    # Detect route definitions
                    if re.search(r"Route::(get|post|put|delete|patch|any)\(", line):
                        # Heuristic: check if middleware is attached in the same line or file context
                        if "middleware" not in line and "->group" not in line:
                            # Check if it's inside a middleware group block (simple check)
                            context = "".join(lines[max(0, i-5):i])
                            if "Route::middleware" not in context:
                                findings.append({
                                    "module": self.module_name,
                                    "issue": f"Potentially unprotected route: {line.strip()}",
                                    "severity": "MEDIUM",
                                    "file": f"{rf}:{i+1}"
                                })
        return findings
