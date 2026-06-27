#!/bin/sh
# Installiert die Abhaengigkeiten fuer die SurfWolf74-Kiosk-Appliance auf Debian.
# Wichtig: python3-pyqt6.qtwebengine ist das System-Paket MIT H.264/AAC-Codecs
# (im Gegensatz zu den pip-Wheels) -> X-Videos funktionieren.
set -e

if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
    python3-pyqt6.qtwebengine \
    xserver-xorg \
    xinit \
    x11-xserver-utils \
    fonts-dejavu-core

echo ""
echo "Fertig. Test in laufender X-Sitzung:  ./kiosk.py"
echo "Echte Appliance: siehe README.md (Autologin + start-kiosk.sh)."
