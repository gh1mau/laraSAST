import subprocess
import json
import shutil
import os

class NucleiWrapper:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Nuclei Engine"

    def scan(self):
        if not shutil.which("nuclei"):
            return [{"module": self.module_name, "issue": "Nuclei not installed", "severity": "INFO"}]

        findings = []
        # Scan file system for misconfigurations using file-based templates
        cmd = [
            "nuclei",
            "-u", self.project_path,
            "-type", "file",
            "-tags", "laravel,config,exposure",
            "-silent",
            "-jsonl"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.stdout:
                for line in result.stdout.splitlines():
                    data = json.loads(line)
                    findings.append({
                        "module": self.module_name,
                        "issue": data.get('info', {}).get('name'),
                        "severity": data.get('info', {}).get('severity').upper(),
                        "file": data.get('matched-at', 'N/A')
                    })
        except Exception as e:
            pass
        
        return findings