#!/usr/bin/env python3
import argparse
from src.scanner import SecretAuditor

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
