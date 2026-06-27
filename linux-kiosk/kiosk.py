#!/usr/bin/env python3
"""SurfWolf74 im Kiosk-/Vollbildmodus starten — OHNE surfwolf74.py zu ändern.

Lädt den Browser und ersetzt zur Laufzeit das Maximieren des Fensters durch
echtes Vollbild (showFullScreen). Die App-Logik bleibt die eine Quelle der
Wahrheit; die Kiosk-Eigenschaft lebt nur hier.

Quelle: bevorzugt surfwolf74.py im Projekt-Root (kanonisch); faellt auf die
lokale Kopie in diesem Verzeichnis zurueck, falls linux-kiosk eigenstaendig
verteilt wird.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

if os.path.exists(os.path.join(ROOT, "surfwolf74.py")):
    sys.path.insert(0, ROOT)
else:
    sys.path.insert(0, HERE)

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
