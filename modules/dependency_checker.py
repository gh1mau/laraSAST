import os
import json
import subprocess
import shutil

class DependencyChecker:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Dependency Analysis (Grype)"

    def scan(self):
        findings = []
        lock_file = os.path.join(self.project_path, "composer.lock")
        
        if not os.path.exists(lock_file):
            return [{"module": self.module_name, "issue": "composer.lock not found", "severity": "LOW"}]
            
        if not shutil.which("grype"):
            return [{"module": self.module_name, "issue": "Grype not installed for deep audit", "severity": "INFO"}]

        try:
            # Menggunakan grype untuk scan direktori (mendukung composer.lock secara otomatis)
            result = subprocess.run(
                ["grype", f"dir:{self.project_path}", "-o", "json", "-q"],
                capture_output=True, text=True, check=True
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for match in data.get('matches', []):
                    vuln = match.get('vulnerability', {})
                    artifact = match.get('artifact', {})

                    # Prefer CVE ID over GHSA if available in related vulnerabilities
                    vuln_id = vuln.get('id', 'N/A')
                    related = vuln.get('relatedVulnerabilities', [])
                    for r in related:
                        if r.get('id', '').startswith('CVE-'):
                            vuln_id = r.get('id')
                            break

                    severity = vuln.get('severity', 'LOW').upper()
                    if severity == "UNKNOWN": severity = "LOW"
                    
                    pkg = artifact.get('name')
                    version = artifact.get('version')
                    
                    cvss_list = vuln.get('cvss', [])
                    cvss_score = cvss_list[0].get('metrics', {}).get('baseScore', 'N/A') if cvss_list else "N/A"

                    findings.append({
                        "module": self.module_name,
                        "issue": f"[{vuln_id}] {pkg}@{version} (CVSS: {cvss_score})",
                        "severity": severity,
                        "file": "composer.lock"
                    })
        except Exception as e:
            findings.append({
                "module": self.module_name,
                "issue": f"Dependency audit failed: {str(e)}",
                "severity": "INFO",
                "file": "N/A"
            })

        return findings
