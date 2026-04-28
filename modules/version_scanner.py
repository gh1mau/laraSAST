import os
import json

class VersionScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Framework Lifecycle Check"
        # Data EOL ringkas (Versi: Tarikh EOL)
        self.eol_versions = {
            "6": "Security fixes until Sep 2022",
            "7": "Security fixes until Sep 2021",
            "8": "Security fixes until Jan 2023",
            "9": "Security fixes until Feb 2024",
        }

    def scan(self):
        findings = []
        composer_file = os.path.join(self.project_path, "composer.json")
        
        if os.path.exists(composer_file):
            try:
                with open(composer_file, 'r') as f:
                    data = json.load(f)
                    laravel_v = data.get('require', {}).get('laravel/framework', '')
                    
                    # Extract major version (e.g., ^9.0 -> 9)
                    major_version = ''.join(filter(str.isdigit, laravel_v.split('.')[0]))
                    
                    if major_version in self.eol_versions:
                        findings.append({
                            "module": self.module_name,
                            "issue": f"Outdated Laravel Version ({laravel_v}). {self.eol_versions[major_version]}",
                            "severity": "HIGH",
                            "file": "composer.json"
                        })
            except Exception:
                pass
        
        return findings