import subprocess
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

# Permissions Android considérées comme dangereuses
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.BLUETOOTH",
    "android.permission.NFC",
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED",
]


class ManifestParser:
    """Parse le AndroidManifest.xml d'un APK via APKTool."""

    def __init__(self, apktool_path: str = None):
        # Cherche apktool.jar dans tools/ par rapport à la racine projet
        root = Path(__file__).resolve().parent.parent.parent
        self.apktool_jar = apktool_path or str(root / "tools" / "apktool.jar")
        self.output_dir = str(root / "uploads" / "decompiled")

    def decompile(self, apk_path: str) -> str:
        """Décompile l'APK avec APKTool et retourne le dossier de sortie."""
        apk_name = Path(apk_path).stem
        out_path = os.path.join(self.output_dir, apk_name)

        print(Fore.CYAN + f"[*] Décompilation de {Path(apk_path).name} avec APKTool...")

        cmd = [
            "java", "-jar", self.apktool_jar,
            "d", apk_path,
            "-o", out_path,
            "-f"  # force : écrase si déjà décompilé
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(Fore.RED + f"[-] Erreur APKTool :\n{result.stderr}")
            return ""

        print(Fore.GREEN + f"[+] Décompilation réussie → {out_path}")
        return out_path

    def parse(self, apk_path: str) -> dict:
        """Pipeline complet : décompile puis analyse le manifest."""

        # 1. Décompiler
        decompiled_path = self.decompile(apk_path)
        if not decompiled_path:
            return {}

        manifest_path = os.path.join(decompiled_path, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            print(Fore.RED + f"[-] AndroidManifest.xml introuvable dans {decompiled_path}")
            return {}

        print(Fore.CYAN + f"[*] Analyse du AndroidManifest.xml...")

        # 2. Parser le XML
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        ns = "http://schemas.android.com/apk/res/android"

        # 3. Infos de base
        package     = root.get("package", "Inconnu")
        version     = root.get(f"{{{ns}}}versionName", "Inconnu")
        min_sdk     = root.find(".//uses-sdk")
        min_sdk_ver = min_sdk.get(f"{{{ns}}}minSdkVersion", "?") if min_sdk is not None else "?"
        target_sdk  = min_sdk.get(f"{{{ns}}}targetSdkVersion", "?") if min_sdk is not None else "?"

        # 4. Permissions
        all_permissions = []
        for perm in root.findall("uses-permission"):
            name = perm.get(f"{{{ns}}}name", "")
            if name:
                all_permissions.append(name)

        dangerous = [p for p in all_permissions if p in DANGEROUS_PERMISSIONS]

        # 5. Flag debug
        app_element = root.find("application")
        is_debug = False
        if app_element is not None:
            debug_val = app_element.get(f"{{{ns}}}debuggable", "false")
            is_debug = debug_val.lower() == "true"

        # 6. Backup autorisé
        allow_backup = True
        if app_element is not None:
            backup_val = app_element.get(f"{{{ns}}}allowBackup", "true")
            allow_backup = backup_val.lower() == "true"

        # 7. Composants exportés (Activities, Services, Receivers)
        exported_components = []
        for tag in ["activity", "service", "receiver", "provider"]:
            for comp in root.findall(f".//{tag}"):
                exported = comp.get(f"{{{ns}}}exported", "")
                name     = comp.get(f"{{{ns}}}name", "Inconnu")
                if exported.lower() == "true":
                    exported_components.append({"type": tag, "name": name})

        # 8. Construire le résultat
        findings = []

        if is_debug:
            findings.append({
                "severity": "HIGH",
                "type":     "Debug mode activé",
                "detail":   "android:debuggable=true expose l'app aux attaques ADB"
            })

        if allow_backup:
            findings.append({
                "severity": "MEDIUM",
                "type":     "Backup autorisé",
                "detail":   "android:allowBackup=true permet d'extraire les données via ADB"
            })

        for perm in dangerous:
            findings.append({
                "severity": "MEDIUM",
                "type":     "Permission dangereuse",
                "detail":   perm
            })

        for comp in exported_components:
            findings.append({
                "severity": "MEDIUM",
                "type":     f"Composant exporté ({comp['type']})",
                "detail":   comp["name"]
            })

        result = {
            "package":              package,
            "version":              version,
            "min_sdk":              min_sdk_ver,
            "target_sdk":           target_sdk,
            "all_permissions":      all_permissions,
            "dangerous_permissions": dangerous,
            "is_debug":             is_debug,
            "allow_backup":         allow_backup,
            "exported_components":  exported_components,
            "findings":             findings,
        }

        # 9. Affichage résumé
        self._print_summary(result)
        return result

    def _print_summary(self, r: dict):
        print(Fore.YELLOW + "\n╔══════════════════════════════════════════╗")
        print(Fore.YELLOW +   "║        ANALYSE ANDROIDMANIFEST.XML       ║")
        print(Fore.YELLOW +   "╚══════════════════════════════════════════╝")
        print(Fore.WHITE  + f"  Package       : {r['package']}")
        print(Fore.WHITE  + f"  Version       : {r['version']}")
        print(Fore.WHITE  + f"  Min SDK       : {r['min_sdk']}")
        print(Fore.WHITE  + f"  Target SDK    : {r['target_sdk']}")
        print(Fore.WHITE  + f"  Permissions   : {len(r['all_permissions'])} totales")

        color = Fore.RED if r['dangerous_permissions'] else Fore.GREEN
        print(color + f"  Dangereuses   : {len(r['dangerous_permissions'])}")

        color = Fore.RED if r['is_debug'] else Fore.GREEN
        print(color + f"  Debug mode    : {'OUI ⚠' if r['is_debug'] else 'NON ✓'}")

        color = Fore.YELLOW if r['allow_backup'] else Fore.GREEN
        print(color + f"  Allow Backup  : {'OUI ⚠' if r['allow_backup'] else 'NON ✓'}")

        print(Fore.WHITE  + f"  Composants exportés : {len(r['exported_components'])}")

        if r['findings']:
            print(Fore.RED + f"\n  [{len(r['findings'])} findings détectés]")
            for f in r['findings']:
                color = Fore.RED if f['severity'] == "HIGH" else Fore.YELLOW
                print(color + f"  [{f['severity']}] {f['type']} : {f['detail']}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(Fore.RED + "Usage : python manifest_parser.py <chemin_vers.apk>")
        sys.exit(1)

    parser = ManifestParser()
    result = parser.parse(sys.argv[1])