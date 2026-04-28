import os
import re

class ConfigHardeningScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Configuration Hardening"

    def scan(self):
        findings = []
        config_dir = os.path.join(self.project_path, "config")
        
        if not os.path.exists(config_dir):
            return findings

        # Map fail ke semakan spesifik (Regex patterns)
        checks = {
            "session.php": [
                (r"'secure'\s*=>\s*env\(['\"]SESSION_SECURE_COOKIE['\"],\s*false\)", "Session cookie 'secure' flag is disabled by default", "MEDIUM"),
                (r"'http_only'\s*=>\s*false", "Session cookie 'http_only' flag is disabled (Risk of XSS cookie theft)", "HIGH"),
                (r"'same_site'\s*=>\s*['\"]null['\"]", "SameSite attribute is null (CSRF risk)", "MEDIUM")
            ],
            "app.php": [
                (r"'debug'\s*=>\s*\(bool\)\s*env\(['\"]APP_DEBUG['\"],\s*true\)", "Application debug mode defaults to true if ENV is missing", "HIGH"),
                (r"'fallback_locale'\s*=>\s*['\"]en['\"]", "Default fallback locale detected (Info Leakage)", "INFO")
            ],
            "database.php": [
                (r"'sslmode'\s*=>\s*['\"]disable['\"]", "Database SSL mode is disabled", "MEDIUM"),
                (r"PDO::MYSQL_ATTR_SSL_CA", None) # Just checking if exists, if not, alert
            ],
            "auth.php": [
                (r"'expire'\s*=>\s*\d{3,}", "Password reset token expiration time is too long", "LOW")
            ]
        }

        for filename, patterns in checks.items():
            file_path = os.path.join(config_dir, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                    # Check specific patterns
                    for pattern, issue, severity in [c for c in patterns if c[1] is not None]:
                        if re.search(pattern, content):
                            findings.append({
                                "module": self.module_name,
                                "issue": issue,
                                "severity": severity,
                                "file": f"config/{filename}"
                            })
                    
                    # Check for missing hardening (Contoh: Database SSL)
                    if filename == "database.php" and "MYSQL_ATTR_SSL_CA" not in content:
                        findings.append({
                            "module": self.module_name,
                            "issue": "Database connection does not appear to use SSL/TLS attributes",
                            "severity": "MEDIUM",
                            "file": f"config/{filename}"
                        })
        
        return findings