#!/bin/sh
# X-Sitzungs-Einstieg fuer die Kiosk-Appliance.
# Wird von startx aufgerufen (siehe README.md). Startet SurfWolf74 im Vollbild
# und in einer Neustart-Schleife, damit ein Absturz den Kiosk nicht beendet.

# Energiesparen / Bildschirmschoner / DPMS abschalten (Kiosk soll immer an sein)
xset s off || true
xset -dpms || true
xset s noblank || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-Neustart bei Absturz
while true; do
    python3 "$SCRIPT_DIR/kiosk.py"
    # Kurze Pause, damit eine Absturzschleife nicht die CPU saettigt
    sleep 2
done
