# 🛡️ APK Security Analyzer

Système automatisé d'analyse de sécurité pour applications Android. Détecte les vulnérabilités et comportements suspects dans les fichiers APK via une interface web moderne.

> Projet réalisé dans le cadre du cours **4CIR - Intrusion & Sécurité Mobile**

---

## 📋 Fonctionnalités

- **Reverse Engineering** automatique via APKTool et JADX
- **Analyse du AndroidManifest.xml** : permissions dangereuses, composants exportés, flags debug/backup
- **Analyse statique du code** : secrets hardcodés, crypto faible (MD5, DES), SQLi patterns, URLs HTTP, logs sensibles
- **Intégration MobSF** : scan complet via API REST
- **Risk Engine** : score de risque pondéré sur 100 avec mapping OWASP Mobile Top 10
- **Interface web** avec upload drag & drop et progression en temps réel (WebSocket)
- **Rapports JSON** exportables

---

## 🏗️ Architecture

```
APK → APKTool/JADX → Static Analyzer → MobSF → Risk Engine → Rapport
```

```
apk-analyzer/
├── src/
│   ├── parsers/
│   │   └── manifest_parser.py     # Analyse AndroidManifest.xml
│   ├── analyzers/
│   │   ├── mobsf_client.py        # Client API MobSF
│   │   └── static_analyzer.py    # Scan regex du code décompilé
│   ├── engine/
│   │   └── risk_engine.py         # Calcul du score de risque
│   └── api/
│       └── app.py                 # Interface web Flask + SocketIO
├── templates/
│   ├── index.html                 # Dashboard upload
│   └── report.html                # Rapport d'analyse
├── tools/
│   ├── apktool.jar                # APKTool 2.9.3
│   └── jadx/                      # JADX 1.5.0
├── uploads/                       # APKs uploadés (gitignore)
├── reports/                       # Rapports générés (gitignore)
└── .env                           # Configuration (gitignore)
```

---

## ⚙️ Prérequis

| Outil | Version | Installation |
|---|---|---|
| Python | 3.10+ | python.org |
| Java JDK | 11 | adoptium.net |
| Docker Desktop | Latest | docker.com |

---

## 🚀 Installation

### 1. Cloner le projet

```bash
git clone https://github.com/Mery-mar/apk-security-analyzer.git
cd apk-security-analyzer
```

### 2. Installer les dépendances Python

```bash
pip install requests flask flask-socketio python-dotenv jinja2 colorama
```

### 3. Télécharger APKTool et JADX

```powershell
# APKTool
Invoke-WebRequest -Uri "https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar" -OutFile "tools\apktool.jar"

# JADX
Invoke-WebRequest -Uri "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip" -OutFile "tools\jadx.zip"
Expand-Archive -Path "tools\jadx.zip" -DestinationPath "tools\jadx"
Remove-Item "tools\jadx.zip"
```

### 4. Lancer MobSF via Docker

```bash
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

### 5. Configurer le fichier .env

```powershell
[System.IO.File]::WriteAllText(".env", "MOBSF_API_KEY=votre_cle_api`nMOBSF_URL=http://localhost:8000`n")
```

> La clé API MobSF est affichée dans les logs au démarrage du container Docker.

### 6. Lancer l'interface web

```bash
python src/api/app.py
```

Ouvrir **http://localhost:5000**

---

## 🔍 Utilisation

1. Ouvrir **http://localhost:5000**
2. Uploader un fichier `.apk` via drag & drop
3. Suivre la progression en temps réel (4 étapes)
4. Consulter le rapport de vulnérabilités

### En ligne de commande

```bash
# Analyse complète
python src/engine/risk_engine.py uploads/monapp.apk

# Manifest uniquement
python src/parsers/manifest_parser.py uploads/monapp.apk

# Analyse statique uniquement
python src/analyzers/static_analyzer.py uploads/decompiled/monapp-java
```

---

## 📊 Exemples de résultats

| Application | Score | Niveau | Findings |
|---|---|---|---|
| InsecureBankv2 | 100/100 | CRITIQUE | 59 |
| Facebook Lite | 100/100 | CRITIQUE | 43 |

---

## 🔬 Détections implémentées

### Manifest Analysis
- Permissions dangereuses (CAMERA, RECORD_AUDIO, READ_SMS...)
- Composants exportés sans protection (Activity, Service, Receiver, Provider)
- Debug mode activé (`android:debuggable=true`)
- Backup ADB autorisé (`android:allowBackup=true`)

### Static Analysis
- Secrets hardcodés (passwords, API keys, tokens)
- Algorithmes cryptographiques faibles (MD5, SHA-1, DES, AES/ECB)
- Injections SQL (rawQuery, execSQL avec concaténation)
- URLs HTTP non chiffrées
- Logs contenant des données sensibles

---

## 🛠️ Stack technique

- **MobSF v4.5.0** — Framework d'analyse mobile
- **APKTool 2.9.3** — Décompilation et extraction du manifest
- **JADX 1.5.0** — Décompilation Java/Kotlin
- **Python 3.11** — Orchestration et analyse
- **Flask + Flask-SocketIO** — Interface web temps réel
- **Docker** — Containerisation de MobSF

---

## 📚 Références

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [MobSF Documentation](https://mobsf.github.io/Mobile-Security-Framework-MobSF/)
- [Android Security Guidelines](https://developer.android.com/topic/security/best-practices)
