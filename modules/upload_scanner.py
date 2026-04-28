import os
import glob

class UploadScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "File Upload Analysis"

    def scan(self):
        findings = []
        controllers = glob.glob(f"{self.project_path}/app/Http/Controllers/**/*.php", recursive=True)

        for controller in controllers:
            with open(controller, 'r') as f:
                content = f.read()
                if "->file(" in content or "Request $request" in content and "->store(" in content:
                    if "validate(" not in content and "mimes:" not in content:
                        findings.append({
                            "module": self.module_name,
                            "issue": "Unvalidated file upload detected",
                            "severity": "CRITICAL",
                            "file": controller
                        })
        return findings
