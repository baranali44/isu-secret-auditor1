#!/usr/bin/env python3
import os
import re
import math
import json
import argparse
from typing import List, Dict

class SecretAuditor:
    def __init__(self, entropy_threshold: float = 3.8):
        self.entropy_threshold = entropy_threshold
        self.findings = []
        # Modern siber güvenlikte en çok aranan hassas veri Regex'leri
        self.patterns = {
            "AWS_ACCESS_KEY": r"(?i)aws_access_key_id\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?",
            "GENERIC_SECRET": r"(?i)(?:secret|token|password|auth_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{16,})['\"]?",
            "PRIVATE_KEY": r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"
        }

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Shannon Entropisi hesaplayarak verinin rastgeleliğini (şifreli/hashli olup olmadığını) ölçer."""
        if not data: return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def scan_file(self, filepath: str):
        """Dosyayı okur ve gizli sızıntıları arar."""
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                for label, regex in self.patterns.items():
                    for match in re.finditer(regex, content):
                        matched_str = match.group(1) if len(match.groups()) > 0 else match.group(0)
                        entropy = self.calculate_entropy(matched_str)
                        
                        # Eğer entropi yüksekse (rastgelelik fazlaysa), bu gerçek bir şifredir.
                        if entropy >= self.entropy_threshold or label == "PRIVATE_KEY":
                            self.findings.append({
                                "file": filepath,
                                "type": label,
                                "entropy": round(entropy, 2),
                                "snippet": matched_str[:20] + "..." # Güvenlik için tamamını gösterme
                            })
        except Exception as e:
            pass # Okunamayan dosyaları atla

    def scan_directory(self, directory: str):
        """Verilen dizindeki tüm dosyaları rekürsif olarak tarar."""
        print(f"[*] Tarama başlatıldı: {directory}")
        for root, _, files in os.walk(directory):
            for file in files:
                self.scan_file(os.path.join(root, file))

    def export_json(self):
        """CI/CD entegrasyonu için bulguları JSON olarak dışa aktarır."""
        return json.dumps(self.findings, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ISU Secret Auditor - Entropy Based String Extractor")
    parser.add_argument("-d", "--dir", required=True, help="Taranacak dizin")
    parser.add_argument("--json", action="store_true", help="Çıktıyı JSON formatında ver (CI/CD için)")
    args = parser.parse_args()

    auditor = SecretAuditor()
    auditor.scan_directory(args.dir)

    if args.json:
        print(auditor.export_json())
    else:
        print("\n[+] TARAMA SONUÇLARI:")
        print("-" * 50)
        if not auditor.findings:
            print("\033[92m[✓] Harika! Herhangi bir hassas veri sızıntısı bulunamadı.\033[0m")
        else:
            for finding in auditor.findings:
                print(f"\033[91m[!] TEHDİT:\033[0m {finding['type']} | Dosya: {finding['file']} | Entropi: {finding['entropy']} | Veri: {finding['snippet']}")
        print("-" * 50)
