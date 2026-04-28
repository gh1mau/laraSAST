import os
import glob
import re

class LogicScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Dangerous Logic Analysis"

    def scan(self):
        findings = []
        # Mencari fungsi berbahaya dan fungsi debugging yang tertinggal
        patterns = {
            r"eval\s*\(": ("Critical: Use of eval() function", "CRITICAL", "Avoid eval(); use safer alternatives or refactor logic."),
            r"shell_exec\s*\(": ("High: Use of shell_exec()", "HIGH", "Use Laravel Process component or avoid OS command execution."),
            r"system\s*\(": ("High: Use of system()", "HIGH", "Use Laravel Process component or avoid OS command execution."),
            r"passthru\s*\(": ("High: Use of passthru()", "HIGH", "Use Laravel Process component or avoid OS command execution."),
            r"exec\s*\(": ("High: Use of exec()", "HIGH", "Use Laravel Process component or avoid OS command execution."),
            r"phpinfo\s*\(": ("Medium: phpinfo() left in code", "MEDIUM", "Remove phpinfo() calls before production deployment."),
            r"\bdd\s*\(": ("Medium: Laravel debug dd() left in code", "MEDIUM", "Remove dd() debugging calls."),
            r"\bdump\s*\(": ("Medium: Laravel debug dump() left in code", "MEDIUM", "Remove dump() debugging calls.")
        }

        files = glob.glob(f"{self.project_path}/app/**/*.php", recursive=True)
        files.extend(glob.glob(f"{self.project_path}/routes/*.php"))

        for file_path in files:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                for pattern, (issue, severity, remediation) in patterns.items():
                    if re.search(pattern, content):
                        findings.append({
                            "module": self.module_name,
                            "issue": issue,
                            "severity": severity,
                            "file": file_path,
                            "remediation": remediation
                        })
        return findings