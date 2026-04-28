import os
import glob
import re

class MassAssignmentScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Eloquent Security"

    def scan(self):
        findings = []
        models = glob.glob(f"{self.project_path}/app/Models/*.php")

        for model in models:
            with open(model, 'r') as f:
                content = f.read()
                # Detect protected $guarded = [];
                if re.search(r"\$guarded\s*=\s*\[\s*\]", content):
                    findings.append({
                        "module": self.module_name,
                        "issue": "Mass Assignment: $guarded is empty. Use $fillable instead for better security.",
                        "severity": "MEDIUM",
                        "file": model
                    })
        return findings