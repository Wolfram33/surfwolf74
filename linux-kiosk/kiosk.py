#!/usr/bin/env python3
"""SurfWolf74 im Kiosk-/Vollbildmodus starten — OHNE surfwolf74.py zu ändern.

Lädt den Browser und ersetzt zur Laufzeit das Maximieren des Fensters durch
echtes Vollbild (showFullScreen). Die App-Logik bleibt die eine Quelle der
Wahrheit; die Kiosk-Eigenschaft lebt nur hier.

Quelle: bevorzugt surfwolf74.py im Projekt-Root (kanonisch). Wird linux-kiosk
eigenstaendig verteilt, greift die Kopie in diesem Verzeichnis – sie liegt
nicht im Repo, sondern wird von debian-package/build.sh hier abgelegt.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
APP_FILE = "surfwolf74.py"

if os.path.exists(os.path.join(ROOT, APP_FILE)):
    sys.path.insert(0, ROOT)
elif os.path.exists(os.path.join(HERE, APP_FILE)):
    sys.path.insert(0, HERE)
else:
    sys.exit(
        f"Fehler: {APP_FILE} nicht gefunden – weder in {ROOT} noch in {HERE}.\n"
        f"Bitte {APP_FILE} aus dem SurfWolf74-Projekt neben kiosk.py kopieren "
        "oder kiosk.py aus dem vollstaendigen Projektordner starten.")

import surfwolf74  # noqa: E402  (Pfad muss vorher gesetzt sein)
from PyQt6.QtWidgets import QMainWindow  # noqa: E402


def _enable_fullscreen():
    """showMaximized() der BrowserWindow auf Vollbild umbiegen (Monkeypatch)."""
    def _show_fullscreen(self):
        QMainWindow.showFullScreen(self)
    surfwolf74.BrowserWindow.showMaximized = _show_fullscreen


if __name__ == "__main__":
    _enable_fullscreen()
    surfwolf74.main()
