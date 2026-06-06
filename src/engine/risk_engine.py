from colorama import Fore, init
from pathlib import Path
from dotenv import load_dotenv

init(autoreset=True)
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / ".env")

# ─── Poids par type de finding ───────────────────────────────────────────────
WEIGHTS = {
    # Manifest findings
    "Debug mode activé":            20,
    "Backup autorisé":              10,
    "Permission dangereuse":         5,
    "Composant exporté (activity)":  8,
    "Composant exporté (service)":   8,
    "Composant exporté (receiver)":  6,
    "Composant exporté (provider)":  9,

    # Static analyzer findings (prochain module)
    "Secret hardcodé":              15,
    "Crypto faible":                12,
    "URL HTTP non chiffrée":         8,
    "SQLi pattern":                 14,
    "Log sensible":                  5,
}

# ─── Seuils de risque ────────────────────────────────────────────────────────
RISK_LEVELS = [
    (80, "CRITIQUE",  Fore.RED),
    (60, "ÉLEVÉ",     Fore.RED),
    (40, "MOYEN",     Fore.YELLOW),
    (20, "FAIBLE",    Fore.GREEN),
    (0,  "MINIMAL",   Fore.GREEN),
]

# ─── Permissions à risque élevé (bonus de score) ─────────────────────────────
HIGH_RISK_PERMISSIONS = [
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
]


class RiskEngine:
    """Calcule un score de risque pondéré à partir des findings."""

    def __init__(self):
        self.findings  = []
        self.penalties = []
        self.score     = 0

    def load_manifest_findings(self, manifest_result: dict):
        """Intègre les findings du ManifestParser."""
        if not manifest_result:
            return

        for f in manifest_result.get("findings", []):
            self.findings.append(f)

        # Bonus de pénalité pour permissions très sensibles
        dangerous = manifest_result.get("dangerous_permissions", [])
        for perm in dangerous:
            if perm in HIGH_RISK_PERMISSIONS:
                self.penalties.append({
                    "reason": f"Permission très sensible : {perm}",
                    "bonus":  5
                })

        print(Fore.CYAN + f"[*] {len(manifest_result.get('findings', []))} findings manifest chargés")

    def load_mobsf_findings(self, mobsf_report: dict):
        """Intègre les findings du rapport MobSF."""
        if not mobsf_report:
            return

        count = 0

        # Récupérer les findings MobSF (section appsec)
        appsec = mobsf_report.get("appsec", {})
        for item in appsec.get("findings", []):
            title    = item.get("title", "")
            severity = item.get("severity", "INFO").upper()
            if severity in ["HIGH", "WARNING", "ERROR"]:
                self.findings.append({
                    "severity": "HIGH" if severity in ["ERROR", "HIGH"] else "MEDIUM",
                    "type":     "MobSF Finding",
                    "detail":   title
                })
                count += 1

        # Score MobSF comme base (inversé : 100 - score MobSF)
        mobsf_score = mobsf_report.get("appsec", {}).get("security_score", 50)
        try:
            base_penalty = max(0, 100 - int(mobsf_score))
            self.penalties.append({
                "reason": f"Score MobSF : {mobsf_score}/100",
                "bonus":  base_penalty // 5
            })
        except (ValueError, TypeError):
            pass

        print(Fore.CYAN + f"[*] {count} findings MobSF chargés")

    def calculate(self) -> dict:
        """Calcule le score de risque final sur 100."""

        raw_score = 0

        # 1. Additionner les poids de chaque finding
        finding_breakdown = {}
        for f in self.findings:
            ftype  = f.get("type", "")
            weight = 0

            # Cherche le poids exact ou par préfixe
            if ftype in WEIGHTS:
                weight = WEIGHTS[ftype]
            else:
                for key in WEIGHTS:
                    if key.lower() in ftype.lower():
                        weight = WEIGHTS[key]
                        break

            sev = f.get("severity", "LOW")
            if sev == "HIGH":
                weight = int(weight * 1.5)

            raw_score += weight
            finding_breakdown[ftype] = finding_breakdown.get(ftype, 0) + 1

        # 2. Ajouter les pénalités bonus
        bonus_total = sum(p["bonus"] for p in self.penalties)
        raw_score  += bonus_total

        # 3. Normaliser sur 100
        final_score = min(100, raw_score)

        # 4. Déterminer le niveau de risque
        risk_label = "MINIMAL"
        risk_color = Fore.GREEN
        for threshold, label, color in RISK_LEVELS:
            if final_score >= threshold:
                risk_label = label
                risk_color = color
                break

        result = {
            "score":             final_score,
            "risk_level":        risk_label,
            "total_findings":    len(self.findings),
            "finding_breakdown": finding_breakdown,
            "penalties":         self.penalties,
            "findings":          self.findings,
        }

        self._print_report(result, risk_color)
        return result

    def _print_report(self, r: dict, risk_color):
        print(Fore.YELLOW + "\n╔══════════════════════════════════════════╗")
        print(Fore.YELLOW +   "║          RAPPORT DE RISQUE GLOBAL        ║")
        print(Fore.YELLOW +   "╚══════════════════════════════════════════╝")

        # Score visuel
        score     = r["score"]
        bar_fill  = int(score / 5)
        bar_empty = 20 - bar_fill
        bar       = "█" * bar_fill + "░" * bar_empty
        print(risk_color + f"\n  Score de risque : {score}/100")
        print(risk_color + f"  [{bar}]")
        print(risk_color + f"  Niveau          : {r['risk_level']}\n")

        print(Fore.WHITE + f"  Total findings  : {r['total_findings']}")

        # Détail par type
        print(Fore.WHITE + "\n  Répartition des findings :")
        for ftype, count in r["finding_breakdown"].items():
            print(Fore.WHITE + f"    • {ftype:<40} x{count}")

        # Pénalités bonus
        if r["penalties"]:
            print(Fore.WHITE + "\n  Pénalités additionnelles :")
            for p in r["penalties"]:
                print(Fore.YELLOW + f"    + {p['bonus']:>3} pts  ← {p['reason']}")

        # Top findings HIGH
        high = [f for f in r["findings"] if f.get("severity") == "HIGH"]
        if high:
            print(Fore.RED + f"\n  Findings critiques ({len(high)}) :")
            for f in high:
                print(Fore.RED + f"    ⚠ {f['type']} : {f['detail']}")

        print(Fore.YELLOW + "\n" + "="*44)


if __name__ == "__main__":
    import sys
    import json
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

    from src.parsers.manifest_parser import ManifestParser
    from src.analyzers.mobsf_client  import MobSFClient

    if len(sys.argv) < 2:
        print(Fore.RED + "Usage : python risk_engine.py <chemin_vers.apk>")
        sys.exit(1)

    apk_path = sys.argv[1]

    # 1. Manifest
    manifest = ManifestParser()
    manifest_result = manifest.parse(apk_path)

    # 2. MobSF
    client = MobSFClient()
    mobsf_result = client.analyze(apk_path)

    # 3. Risk Engine
    engine = RiskEngine()
    engine.load_manifest_findings(manifest_result)
    engine.load_mobsf_findings(mobsf_result.get("report", {}))
    final = engine.calculate()

    # 4. Sauvegarder le résultat JSON
    out_path = Path(__file__).resolve().parent.parent.parent / "reports" / "risk_report.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(final, f, indent=2, ensure_ascii=False)

    print(Fore.GREEN + f"\n[+] Rapport JSON sauvegardé → {out_path}")