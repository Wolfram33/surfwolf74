# SurfWolf74

Ein moderner, datensparsamer Webbrowser auf Basis von PyQt6 und Chromium
(QtWebEngine). Läuft unter **Windows und Linux** (Debian/Ubuntu).

![SurfWolf74](screenshot-surfwolf74.jpg)

## Features

- Tab-basiertes Browsing
- Lesezeichen-Verwaltung (mit Drag & Drop)
- Website-Blocker
- Dark Mode und individuelle Farbthemen
- Website-Farben invertieren (Invert-Modus)
- JavaScript zur Laufzeit aktivieren/deaktivieren
- Normaler und strikter Sicherheitsmodus (Privacy-Header, Anti-Fingerprinting)
- Anpassbare Startseite
- Verschiebbare Toolbars (Position wird gemerkt)
- Aktuelle Seite im System-Browser öffnen (Strg+E)

## Voraussetzungen

- Python 3.10+
- PyQt6
- PyQt6-WebEngine

## Installation und Start

### Aus dem Quellcode (Windows & Linux)

```bash
pip install PyQt6 PyQt6-WebEngine
python surfwolf74.py
```

### Linux: natives Paket (Debian/Ubuntu)

Im Verzeichnis [`linux-kiosk/`](linux-kiosk/) liegt ein nativer `.deb`-Installer.
Er nutzt Debians **System-QtWebEngine** und installiert alle Abhängigkeiten
automatisch:

```bash
sh linux-kiosk/debian-package/build.sh                  # erzeugt surfwolf74_<version>_all.deb
sudo apt install ./linux-kiosk/surfwolf74_<version>_all.deb
```

Danach ist „SurfWolf74" im Anwendungsmenü und über den Befehl `surfwolf74`
verfügbar.

## Videowiedergabe / Codecs (wichtig)

QtWebEngine spielt MP4/H.264-Videos nur mit proprietären Codecs ab.

- **Windows / pip-Wheels:** ohne H.264 gebaut. Seiten, die ausschließlich
  H.264 streamen (z. B. x.com), spielen **nicht im Browser** – dafür gibt es
  den Button **„🌐 Extern" (Strg+E)**, der die Seite im System-Browser öffnet.
  YouTube u. a. (VP9) funktionieren normal.
- **Linux (Debian/Ubuntu, System-Paket):** `python3-pyqt6.qtwebengine` ist
  **mit** H.264/AAC gebaut – dort spielt auch x.com direkt im Browser.

## Build / Distribution

- **Windows:** Kompilieren mit [Nuitka](https://nuitka.net/) – der genaue
  Befehl steht in [`kombilieren.txt`](kombilieren.txt). Der Windows-Installer
  wird anschließend mit Inno Setup gepackt.
- **Linux:** siehe `.deb`-Installer oben.

## Linux-Kiosk-Appliance (optional)

[`linux-kiosk/`](linux-kiosk/) enthält außerdem die Bausteine, um einen PC
direkt in SurfWolf74 booten zu lassen (Vollbild, kein Desktop) – inklusive
`kiosk.py` (Vollbild-Start ohne Änderung am Browser) und Autostart-Skripten.
Details in [`linux-kiosk/README.md`](linux-kiosk/README.md).

## Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).

## Autor

Rob de Roy — [Wolfram Consult GmbH & Co. KG](https://wolfram-consult.com)
