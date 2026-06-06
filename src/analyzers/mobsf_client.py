import requests
import os
from dotenv import load_dotenv
from colorama import Fore, Style, init

init(autoreset=True)
from pathlib import Path
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / ".env")

MOBSF_URL = os.getenv("MOBSF_URL", "http://localhost:8000")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY")


class MobSFClient:
    """Client pour interagir avec l'API REST de MobSF."""

    def __init__(self):
        if not MOBSF_API_KEY:
            raise ValueError("MOBSF_API_KEY manquante dans le fichier .env")
        self.base_url = MOBSF_URL
        self.headers = {"Authorization": MOBSF_API_KEY}
        print(Fore.GREEN + f"[+] MobSFClient initialisé → {self.base_url}")

    def upload(self, apk_path: str) -> dict:
        """Upload un fichier APK vers MobSF et retourne le hash."""
        if not os.path.exists(apk_path):
            print(Fore.RED + f"[-] Fichier introuvable : {apk_path}")
            return {}

        print(Fore.CYAN + f"[*] Upload de {os.path.basename(apk_path)}...")

        with open(apk_path, "rb") as apk_file:
            files = {"file": (os.path.basename(apk_path), apk_file, "application/octet-stream")}
            response = requests.post(
                f"{self.base_url}/api/v1/upload",
                files=files,
                headers=self.headers
            )

        if response.status_code == 200:
            data = response.json()
            print(Fore.GREEN + f"[+] Upload réussi → hash : {data.get('hash')}")
            return data
        else:
            print(Fore.RED + f"[-] Erreur upload : {response.status_code} - {response.text}")
            return {}

    def scan(self, hash: str, file_name: str) -> dict:
        """Lance l'analyse statique d'un APK déjà uploadé."""
        print(Fore.CYAN + f"[*] Lancement du scan pour {file_name}...")

        payload = {"hash": hash, "re_scan": 0}
        response = requests.post(
            f"{self.base_url}/api/v1/scan",
            data=payload,
            headers=self.headers
        )

        if response.status_code == 200:
            print(Fore.GREEN + f"[+] Scan terminé ✓")
            return response.json()
        else:
            print(Fore.RED + f"[-] Erreur scan : {response.status_code} - {response.text}")
            return {}

    def get_report(self, hash: str) -> dict:
        """Récupère le rapport JSON complet d'une analyse."""
        print(Fore.CYAN + f"[*] Récupération du rapport...")

        response = requests.post(
            f"{self.base_url}/api/v1/report_json",
            data={"hash": hash},
            headers=self.headers
        )

        if response.status_code == 200:
            print(Fore.GREEN + f"[+] Rapport récupéré ✓")
            return response.json()
        else:
            print(Fore.RED + f"[-] Erreur rapport : {response.status_code} - {response.text}")
            return {}

    def get_score(self, report: dict) -> dict:
        """Extrait le score de sécurité et les infos clés du rapport."""
        if not report:
            return {}

        score_data = {
            "app_name":    report.get("app_name", "Inconnu"),
            "package":     report.get("package_name", "Inconnu"),
            "version":     report.get("version_name", "Inconnu"),
            "min_sdk":     report.get("min_sdk", "Inconnu"),
            "target_sdk":  report.get("target_sdk", "Inconnu"),
            "security_score": report.get("appsec", {}).get("security_score", "N/A"),
            "total_findings": len(report.get("findings", {})),
            "permissions": len(report.get("permissions", {})),
            "activities":  len(report.get("activities", [])),
        }

        print(Fore.YELLOW + "\n╔══════════════════════════════════════╗")
        print(Fore.YELLOW +   "║         RÉSUMÉ DE L'ANALYSE          ║")
        print(Fore.YELLOW +   "╚══════════════════════════════════════╝")
        for key, val in score_data.items():
            print(Fore.WHITE + f"  {key:<20} : {val}")

        return score_data

    def analyze(self, apk_path: str) -> dict:
        """Pipeline complet : upload → scan → rapport → score."""
        print(Fore.YELLOW + "\n" + "="*40)
        print(Fore.YELLOW + "   ANALYSE APK DÉMARRÉE")
        print(Fore.YELLOW + "="*40 + "\n")

        # 1. Upload
        upload_data = self.upload(apk_path)
        if not upload_data:
            return {}

        hash_value = upload_data.get("hash")
        file_name  = upload_data.get("file_name", os.path.basename(apk_path))

        # 2. Scan
        self.scan(hash_value, file_name)

        # 3. Rapport
        report = self.get_report(hash_value)

        # 4. Score
        score = self.get_score(report)

        return {"hash": hash_value, "report": report, "score": score}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(Fore.RED + "Usage : python mobsf_client.py <chemin_vers.apk>")
        sys.exit(1)

    client = MobSFClient()
    result = client.analyze(sys.argv[1])
