import os
import re

class EnvScanner:
    def __init__(self, project_path):
        self.project_path = project_path
        self.module_name = "Environment Analysis"

    def scan(self):
        findings = []
        env_path = os.path.join(self.project_path, ".env")
        
        if not os.path.exists(env_path):
            return [{"module": self.module_name, "issue": ".env file missing", "severity": "MEDIUM", "file": ".env"}]

        with open(env_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if "APP_DEBUG=true" in line:
                    findings.append({"module": self.module_name, "issue": "Debug mode enabled in .env", "severity": "HIGH", "file": ".env"})
                if "DB_PASSWORD=" in line and len(line.strip().split('=')[1]) == 0:
                    findings.append({"module": self.module_name, "issue": "Empty Database Password", "severity": "CRITICAL", "file": ".env"})
                if "APP_ENV=production" in line and "APP_DEBUG=true" in line:
                    findings.append({"module": self.module_name, "issue": "Production debug mode", "severity": "CRITICAL", "file": ".env"})
                if "APP_KEY=" in line and (len(line.strip().split('=')[1]) < 10):
                    findings.append({"module": self.module_name, "issue": "Missing or weak APP_KEY (risk of decryption)", "severity": "CRITICAL", "file": ".env"})
                if "SESSION_SECURE_COOKIE=false" in line:
                    findings.append({"module": self.module_name, "issue": "Insecure session cookies (HTTPS only recommended)", "severity": "MEDIUM", "file": ".env"})
                if "MAIL_HOST=smtp.mailtrap.io" in line and "APP_ENV=production" in line:
                    findings.append({"module": self.module_name, "issue": "Mailtrap detected in production", "severity": "HIGH", "file": ".env"})
                if any(x in line for x in ["AWS_SECRET_ACCESS_KEY=", "STRIPE_SECRET="]) and len(line.strip().split('=')[1]) > 5:
                    findings.append({"module": self.module_name, "issue": "Cloud/Payment Secret hardcoded in .env", "severity": "HIGH", "file": ".env"})
        
        return findings
