import os
import sys
import json
import re
from pathlib import Path
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
from colorama import Fore, init

# ─── Setup chemins ────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(dotenv_path=ROOT / ".env")
init(autoreset=True)

from src.parsers.manifest_parser import ManifestParser
from src.analyzers.mobsf_client  import MobSFClient
from src.analyzers.static_analyzer import StaticAnalyzer
from src.engine.risk_engine      import RiskEngine

# ─── Flask App ────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder=str(ROOT / "templates"))
app.config["SECRET_KEY"] = "apk-analyzer-secret"
socketio = SocketIO(app, cors_allowed_origins="*")

UPLOAD_FOLDER  = ROOT / "uploads"
REPORTS_FOLDER = ROOT / "reports"
ALLOWED_EXT    = {"apk"}

os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def progress(sid, step, total, message, percent):
    """Envoie une mise à jour de progression au client."""
    socketio.emit("progress", {
        "step":    step,
        "total":   total,
        "message": message,
        "percent": percent,
    }, room=sid)
    socketio.sleep(0)


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    reports = []
    for f in REPORTS_FOLDER.glob("*.json"):
        try:
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
            reports.append({
                "filename": f.name,
                "score":    data.get("score", "N/A"),
                "level":    data.get("risk_level", "N/A"),
                "total":    data.get("total_findings", 0),
                "app_name": data.get("app_name", f.stem),
            })
        except Exception:
            pass
    reports.sort(key=lambda x: x["filename"], reverse=True)
    return render_template("index.html", reports=reports)


@app.route("/analyze", methods=["POST"])
def analyze():
    sid = request.form.get("sid", "")

    if "apk" not in request.files:
        return jsonify({"error": "Aucun fichier APK fourni"}), 400

    file = request.files["apk"]
    if file.filename == "" or not allowed_file(file.filename):
        return jsonify({"error": "Fichier invalide"}), 400

    # Nettoyer le nom de fichier
    clean_name = re.sub(r'[^a-zA-Z0-9._-]', '_', file.filename)
    apk_path   = UPLOAD_FOLDER / clean_name
    file.save(str(apk_path))
    apk_stem = Path(clean_name).stem

    print(Fore.GREEN + f"[+] APK reçu : {clean_name}")

    try:
        # ── Étape 1 : Manifest Parser ──────────────────────────────────────
        progress(sid, 1, 4, "Décompilation et analyse du AndroidManifest.xml...", 10)
        manifest = ManifestParser()
        manifest_result = manifest.parse(str(apk_path))
        progress(sid, 1, 4, f"Manifest analysé — {len(manifest_result.get('findings', []))} findings", 25)

        # ── Étape 2 : Static Analyzer ──────────────────────────────────────
        progress(sid, 2, 4, "Décompilation Java avec JADX...", 30)
        jadx_out = UPLOAD_FOLDER / "decompiled" / f"{apk_stem}-java"
        jadx_bat = ROOT / "tools" / "jadx" / "bin" / "jadx.bat"
        os.makedirs(jadx_out, exist_ok=True)
        os.system(f'"{jadx_bat}" -d "{jadx_out}" "{apk_path}"')

        progress(sid, 2, 4, "Scan statique du code décompilé...", 45)
        static = StaticAnalyzer()
        static.scan_directory(str(jadx_out))
        static_result = static.get_summary()
        progress(sid, 2, 4, f"Analyse statique — {static_result.get('total', 0)} findings", 55)

        # ── Étape 3 : MobSF ────────────────────────────────────────────────
        progress(sid, 3, 4, "Upload vers MobSF...", 60)
        client = MobSFClient()
        upload_data = client.upload(str(apk_path))

        progress(sid, 3, 4, "Scan MobSF en cours (peut prendre quelques minutes)...", 65)
        hash_value = upload_data.get("hash", "")
        file_name  = upload_data.get("file_name", clean_name)
        client.scan(hash_value, file_name)

        progress(sid, 3, 4, "Récupération du rapport MobSF...", 80)
        mobsf_report = client.get_report(hash_value)
        mobsf_score  = client.get_score(mobsf_report)
        mobsf_result = {"hash": hash_value, "report": mobsf_report, "score": mobsf_score}
        progress(sid, 3, 4, f"MobSF terminé — score {mobsf_score.get('security_score', 'N/A')}/100", 85)

        # ── Étape 4 : Risk Engine ──────────────────────────────────────────
        progress(sid, 4, 4, "Calcul du score de risque global...", 90)
        engine = RiskEngine()
        engine.load_manifest_findings(manifest_result)
        engine.load_mobsf_findings(mobsf_result.get("report", {}))
        for f in static_result.get("findings", []):
            engine.findings.append({
                "severity": f.get("severity", "MEDIUM"),
                "type":     f.get("type", "Static Finding"),
                "detail":   f.get("snippet", f.get("detail", "")),
            })

        final = engine.calculate()
        final["app_name"]    = mobsf_score.get("app_name", apk_stem)
        final["package"]     = manifest_result.get("package", "Inconnu")
        final["version"]     = mobsf_score.get("version", "Inconnu")
        final["manifest"]    = manifest_result
        final["static"]      = static_result
        final["mobsf_score"] = mobsf_score

        # Sauvegarder
        report_path = REPORTS_FOLDER / f"{apk_stem}_report.json"
        with open(report_path, "w", encoding="utf-8") as fp:
            json.dump(final, fp, indent=2, ensure_ascii=False)

        progress(sid, 4, 4, f"Analyse terminée — Score {final['score']}/100 {final['risk_level']}", 100)
        print(Fore.GREEN + f"[+] Analyse terminée -> {report_path}")

        return redirect(url_for("report", filename=f"{apk_stem}_report.json"))

    except Exception as e:
        print(Fore.RED + f"[-] Erreur : {e}")
        socketio.emit("error", {"message": str(e)}, room=sid)
        return jsonify({"error": str(e)}), 500


@app.route("/report/<filename>")
def report(filename):
    report_path = REPORTS_FOLDER / filename
    if not report_path.exists():
        return "Rapport introuvable", 404
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)
    return render_template("report.html", data=data, filename=filename)


@app.route("/api/report/<filename>")
def api_report(filename):
    report_path = REPORTS_FOLDER / filename
    if not report_path.exists():
        return jsonify({"error": "Rapport introuvable"}), 404
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data)


@app.route("/api/status")
def status():
    return jsonify({"status": "ok", "mobsf": os.getenv("MOBSF_URL"), "version": "1.0.0"})


@socketio.on("connect")
def on_connect():
    print(Fore.CYAN + f"[WS] Client connecté : {request.sid}")


@socketio.on("disconnect")
def on_disconnect():
    print(Fore.CYAN + f"[WS] Client déconnecté : {request.sid}")


if __name__ == "__main__":
    print("""
APK Security Analyzer - v1.0
http://localhost:5000
""")
    socketio.run(app, debug=True, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
