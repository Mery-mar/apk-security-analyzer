import os
import re
from pathlib import Path
from colorama import Fore, init

init(autoreset=True)

# ─── Patterns de détection ────────────────────────────────────────────────────

PATTERNS = {
    "Secret hardcodé": [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',    "HIGH"),
        (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][^"\']{8,}["\']', "HIGH"),
        (r'(?i)(secret|token|auth)\s*[=:]\s*["\'][^"\']{8,}["\']',      "HIGH"),
        (r'(?i)(private_key|privatekey)\s*[=:]\s*["\'][^"\']{8,}["\']', "HIGH"),
    ],
    "URL HTTP non chiffrée": [
        (r'http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}',                      "MEDIUM"),
    ],
    "Crypto faible": [
        (r'(?i)MessageDigest\.getInstance\(["\']MD5["\']',               "HIGH"),
        (r'(?i)MessageDigest\.getInstance\(["\']SHA-1["\']',             "MEDIUM"),
        (r'(?i)Cipher\.getInstance\(["\']DES["\']',                      "HIGH"),
        (r'(?i)Cipher\.getInstance\(["\']RC4["\']',                      "HIGH"),
        (r'(?i)Cipher\.getInstance\(["\']AES/ECB',                       "HIGH"),
        (r'(?i)SecretKeySpec\(.*["\']DES["\']',                          "HIGH"),
    ],
    "SQLi pattern": [
        (r'(?i)rawQuery\s*\(\s*["\'][^"\']*\+',                         "HIGH"),
        (r'(?i)execSQL\s*\(\s*["\'][^"\']*\+',                          "HIGH"),
        (r'(?i)"SELECT.*"\s*\+',                                         "HIGH"),
        (r'(?i)"INSERT.*"\s*\+',                                         "MEDIUM"),
        (r'(?i)"UPDATE.*"\s*\+',                                         "MEDIUM"),
    ],
    "Log sensible": [
        (r'(?i)Log\.[dvwei]\s*\([^,]+,\s*["\'][^"\']{0,}(password|token|key|secret)',  "MEDIUM"),
        (r'(?i)System\.out\.println\s*\([^)]{0,}(password|token|key)',                 "MEDIUM"),
    ],
}

# Extensions de fichiers à analyser
SCAN_EXTENSIONS = {".java", ".kt", ".xml", ".smali"}

# Dossiers à ignorer
IGNORE_DIRS = {"res", "assets", "META-INF", "original"}


class StaticAnalyzer:
    """Analyse statique du code décompilé par JADX/APKTool."""

    def __init__(self):
        self.findings = []

    def scan_directory(self, decompiled_path: str) -> list:
        """Scanne récursivement tous les fichiers décompilés."""
        if not os.path.exists(decompiled_path):
            print(Fore.RED + f"[-] Dossier introuvable : {decompiled_path}")
            return []

        print(Fore.CYAN + f"[*] Scan statique de {decompiled_path}...")

        total_files = 0
        self.findings = []

        for root, dirs, files in os.walk(decompiled_path):
            # Ignorer certains dossiers
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

            for filename in files:
                ext = Path(filename).suffix.lower()
                if ext not in SCAN_EXTENSIONS:
                    continue

                filepath = os.path.join(root, filename)
                total_files += 1

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        lines   = content.splitlines()

                    self._scan_file(filepath, lines, decompiled_path)

                except Exception as e:
                    pass  # Ignorer les fichiers illisibles

        print(Fore.GREEN + f"[+] {total_files} fichiers scannés → {len(self.findings)} findings")
        return self.findings

    def _scan_file(self, filepath: str, lines: list, base_path: str):
        """Applique tous les patterns sur un fichier."""
        rel_path = os.path.relpath(filepath, base_path)

        # Ignorer les librairies tierces
        ignore_paths = ["android\\support", "androidx", "smali\\com\\google",
                        "smali\\android", "smali\\com\\squareup", "smali\\okhttp"]
        if any(x in rel_path for x in ignore_paths):
            return

        for pattern_type, pattern_list in PATTERNS.items():
            for pattern, severity in pattern_list:
                for line_num, line in enumerate(lines, 1):
                    match = re.search(pattern, line)
                    if match:
                        # Éviter les doublons sur la même ligne
                        existing = any(
                            f["file"] == rel_path and
                            f["line"] == line_num and
                            f["type"] == pattern_type
                            for f in self.findings
                        )
                        if not existing:
                            self.findings.append({
                                "type":     pattern_type,
                                "severity": severity,
                                "file":     rel_path,
                                "line":     line_num,
                                "snippet":  line.strip()[:120],
                                "pattern":  pattern,
                            })

    def get_summary(self) -> dict:
        """Retourne un résumé des findings par type et sévérité."""
        summary = {
            "total":    len(self.findings),
            "high":     len([f for f in self.findings if f["severity"] == "HIGH"]),
            "medium":   len([f for f in self.findings if f["severity"] == "MEDIUM"]),
            "by_type":  {},
            "findings": self.findings,
        }

        for f in self.findings:
            t = f["type"]
            summary["by_type"][t] = summary["by_type"].get(t, 0) + 1

        self._print_summary(summary)
        return summary

    def _print_summary(self, s: dict):
        print(Fore.YELLOW + "\n╔══════════════════════════════════════════╗")
        print(Fore.YELLOW +   "║         ANALYSE STATIQUE DU CODE         ║")
        print(Fore.YELLOW +   "╚══════════════════════════════════════════╝")
        print(Fore.WHITE  + f"  Total findings : {s['total']}")
        print(Fore.RED    + f"  HIGH           : {s['high']}")
        print(Fore.YELLOW + f"  MEDIUM         : {s['medium']}")

        print(Fore.WHITE + "\n  Par type :")
        for ftype, count in s["by_type"].items():
            print(Fore.WHITE + f"    • {ftype:<35} x{count}")

        # Afficher les findings HIGH en détail
        high_findings = [f for f in s["findings"] if f["severity"] == "HIGH"]
        if high_findings:
            print(Fore.RED + f"\n  Détail findings HIGH ({len(high_findings)}) :")
            for f in high_findings[:15]:  # max 15 affichés
                print(Fore.RED    + f"\n  ⚠ [{f['severity']}] {f['type']}")
                print(Fore.WHITE  + f"    Fichier  : {f['file']}")
                print(Fore.WHITE  + f"    Ligne    : {f['line']}")
                print(Fore.YELLOW + f"    Code     : {f['snippet']}")

        # Afficher quelques MEDIUM
        medium_findings = [f for f in s["findings"] if f["severity"] == "MEDIUM"]
        if medium_findings:
            print(Fore.YELLOW + f"\n  Détail findings MEDIUM (premiers 5) :")
            for f in medium_findings[:5]:
                print(Fore.YELLOW + f"\n  ~ [{f['severity']}] {f['type']}")
                print(Fore.WHITE  + f"    Fichier  : {f['file']}")
                print(Fore.WHITE  + f"    Ligne    : {f['line']}")
                print(Fore.WHITE  + f"    Code     : {f['snippet']}")


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print(Fore.RED + "Usage : python static_analyzer.py <chemin_vers_dossier_decompile>")
        print(Fore.YELLOW + "Ex    : python static_analyzer.py uploads\\decompiled\\InsecureBankv2")
        sys.exit(1)

    decompiled_path = sys.argv[1]

    analyzer = StaticAnalyzer()
    analyzer.scan_directory(decompiled_path)
    summary = analyzer.get_summary()

    # Sauvegarder
    root     = Path(__file__).resolve().parent.parent.parent
    out_path = root / "reports" / "static_analysis.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(Fore.GREEN + f"\n[+] Rapport sauvegardé → {out_path}")