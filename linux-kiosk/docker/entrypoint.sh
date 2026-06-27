#!/bin/sh
# Startet virtuelles Display, Fenstermanager, VNC + noVNC und den Browser.
set -e

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# 1. Virtuelles Display
Xvfb :99 -screen 0 1280x800x24 -ac +extension GLX +render -noreset >/tmp/xvfb.log 2>&1 &

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
websockify --web=/usr/share/novnc 8080 localhost:5900 >/tmp/novnc.log 2>&1 &
sleep 0.5

echo "------------------------------------------------------------"
echo " SurfWolf74-Test laeuft. Im Browser oeffnen:"
echo "   http://localhost:8080/vnc.html   (dann 'Connect')"
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
