#!/bin/sh
# Startet virtuelles Display, Fenstermanager, VNC + noVNC und den Browser.
set -e

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# 1. Virtuelles Display (Aufloesung via SCREEN ueberschreibbar, z. B. 1600x900)
SCREEN_RES="${SCREEN:-1920x1080}"
Xvfb :99 -screen 0 "${SCREEN_RES}x24" -ac +extension GLX +render -noreset >/tmp/xvfb.log 2>&1 &

# Warten bis das Display bereit ist
for i in $(seq 1 30); do
    if xdpyinfo -display :99 >/dev/null 2>&1; then break; fi
    sleep 0.3
done

# 2. Minimaler Fenstermanager (Fokus/Resize fuer das Browserfenster)
openbox >/tmp/openbox.log 2>&1 &
sleep 0.5

# 3. VNC-Server auf das Display (ohne Passwort, nur lokal gedacht)
x11vnc -display :99 -nopw -forever -shared -rfbport 5900 -quiet >/tmp/x11vnc.log 2>&1 &
sleep 0.5

# 4. noVNC: Web-Frontend auf 8080 -> Bruecke zu VNC 5900
# Wurzel-URL automatisch auf vnc.html mit Auto-Connect + Skalierung umleiten,
# damit das Browserfenster das ganze Fenster fuellt (kein kleiner Rahmen).
printf '%s\n' '<!doctype html><meta http-equiv="refresh" content="0; url=vnc.html?autoconnect=true&resize=scale">' \
    > /usr/share/novnc/index.html
websockify --web=/usr/share/novnc 8080 localhost:5900 >/tmp/novnc.log 2>&1 &
sleep 0.5

echo "------------------------------------------------------------"
echo " SurfWolf74-Test laeuft. Im Browser oeffnen:"
echo "   http://localhost:8080/        (verbindet automatisch, skaliert)"
echo "------------------------------------------------------------"

# 5. Browser starten und bei Beenden automatisch neu starten
cd /opt/surfwolf74
if [ "$KIOSK" = "1" ]; then
    APP="kiosk.py"
else
    APP="surfwolf74.py"
fi
while true; do
    python3 "$APP" || true
    echo "Browser beendet - Neustart in 2s..."
    sleep 2
done
