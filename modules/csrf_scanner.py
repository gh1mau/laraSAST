import os
import re

class CsrfScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "CSRF Protection Analysis"

    def scan(self):
        findings = []
        # Lokasi standard VerifyCsrfToken middleware
        csrf_file = os.path.join(self.project_path, "app/Http/Middleware/VerifyCsrfToken.php")
        
        if os.path.exists(csrf_file):
            with open(csrf_file, 'r') as f:
                content = f.read()
                # Mencari kandungan dalam array $except
                match = re.search(r"protected\s+\$except\s*=\s*\[(.*?)\];", content, re.DOTALL)
                if match:
                    excepted_routes = match.group(1).strip()
                    if excepted_routes:
                        severity = "HIGH" if "*" in excepted_routes else "MEDIUM"
                        findings.append({
                            "module": self.module_name,
                            "issue": f"CSRF protection disabled for specific routes: {excepted_routes[:50]}...",
                            "severity": severity,
                            "file": "app/Http/Middleware/VerifyCsrfToken.php"
                        })
        return findings