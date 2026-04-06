import os
import re
import math
import json

class SecretAuditor:
    def __init__(self, entropy_threshold: float = 3.8):
        self.entropy_threshold = entropy_threshold
        self.findings = []
        self.patterns = {
            "AWS_ACCESS_KEY": r"(?i)aws_access_key_id\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?",
            "GENERIC_SECRET": r"(?i)(?:secret|token|password|auth_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{16,})['\"]?",
            "PRIVATE_KEY": r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"
        }

    @staticmethod
    def calculate_entropy(data: str) -> float:
        if not data: return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def scan_file(self, filepath: str):
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                for label, regex in self.patterns.items():
                    for match in re.finditer(regex, content):
                        matched_str = match.group(1) if len(match.groups()) > 0 else match.group(0)
                        entropy = self.calculate_entropy(matched_str)
                        if entropy >= self.entropy_threshold or label == "PRIVATE_KEY":
                            self.findings.append({
                                "file": filepath, "type": label,
                                "entropy": round(entropy, 2),
                                "snippet": matched_str[:20] + "..."
                            })
        except Exception:
            pass 

    def scan_directory(self, directory: str):
        print(f"[*] Tarama başlatıldı: {directory}")
        for root, _, files in os.walk(directory):
            for file in files:
                self.scan_file(os.path.join(root, file))

    def export_json(self):
        return json.dumps(self.findings, indent=4)
