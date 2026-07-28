# Windows-Build (automatisch via GitHub Actions)

Bei jedem Push auf `master` baut GitHub automatisch die Windows-Version und
veröffentlicht sie als **öffentliches Prerelease „latest-dev"**:

- **SurfWolf74-Setup.exe** – Installer (Inno Setup)
- **SurfWolf74-portable.zip** – entpacken und `surfwolf74.exe` starten (kein Setup)

👉 Download: **Releases → „Latest development build"** auf der GitHub-Seite.

## Ablauf des Workflows
Datei: [`.github/workflows/build-windows.yml`](../.github/workflows/build-windows.yml)

1. Python 3.12 + PyQt6/WebEngine + Nuitka installieren
2. FFmpeg-DLLs herunterladen (nicht im Repo, da zu groß)
3. `surfwolf74.exe` mit **Nuitka** bauen (identisch zu [`kombilieren.txt`](../kombilieren.txt))
4. Installer mit **Inno Setup** aus [`setup.iss`](setup.iss) erzeugen (Version kommt aus `APP_VERSION`)
5. Beides ins Release „latest-dev" hochladen

## Manuell auslösen
GitHub → **Actions** → „Windows Build" → **Run workflow**.

## Hinweise
- Der Build dauert ~15–30 Min (Nuitka + QtWebEngine).
- „latest-dev" ist ein **Entwicklungs-Build**, kein stabiles Release. Für feste
  Versionen später einen Git-Tag (`v5.2`) nutzen – das lässt sich leicht ergänzen.
- Lokaler Build unverändert möglich über `kombilieren.txt`.
