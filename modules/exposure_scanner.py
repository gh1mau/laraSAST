import os

class ExposureScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Information Exposure"

    def scan(self):
        findings = []
        # Senarai fail/folder sensitif dari laravel-audit-tool
        sensitive_paths = {
            ".git": "Git repository metadata exposed",
            "storage/logs/laravel.log": "Laravel log file detected (Sensitive info leak)",
            ".env.bak": "Backup environment file detected",
            ".env.old": "Old environment file detected",
            "composer.json": "Composer configuration (Version fingerprinting)",
            "phpinfo.php": "PHP info file detected",
            "server.php": "Laravel built-in server script exposed"
        }

        for path, issue in sensitive_paths.items():
            full_path = os.path.join(self.project_path, path)
            if os.path.exists(full_path):
                severity = "HIGH" if ".env" in path or ".git" in path else "MEDIUM"
                if "composer" in path: severity = "INFO"
                
                findings.append({
                    "module": self.module_name,
                    "issue": issue,
                    "severity": severity,
                    "file": path
                })
        return findings