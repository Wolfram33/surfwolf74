# Test-Container fuer SurfWolf74 unter Linux.
# Nutzt Debians System-QtWebEngine (inkl. H.264 -> X-Videos) und stellt den
# Browser per noVNC im Web bereit: http://localhost:8080/vnc.html
#
# Build (aus dem Projekt-Root):
#   docker build -f linux-kiosk/docker/Dockerfile -t surfwolf74-test .
# Start:
#   docker run --rm -p 8080:8080 surfwolf74-test
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:99 \
    QTWEBENGINE_DISABLE_SANDBOX=1 \
    QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu --disable-dev-shm-usage"

# System-QtWebEngine (mit Codecs) + virtuelles Display + VNC/noVNC + Mini-WM
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-pyqt6.qtwebengine \
        xvfb x11vnc novnc websockify openbox \
        x11-xserver-utils fonts-dejavu-core ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# App + Assets (Build-Kontext = Projekt-Root)
WORKDIR /opt/surfwolf74
COPY surfwolf74.py ./
COPY surfwolf74.png icon.ico icon.png folder.png ./
COPY bookmarks.json config.json blocked_sites.json ./
COPY linux-kiosk/kiosk.py ./kiosk.py
COPY linux-kiosk/docker/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

# noVNC-Weboberflaeche
EXPOSE 8080

# Vollbild (kiosk.py) ist die Standard-Testansicht und rendert im Headless-X
# zuverlaessig zentriert. KIOSK=0 -> normales Fenster (kann im Container wegen
# des Maximier-Timings versetzt rendern).
ENV KIOSK=1
CMD ["/entrypoint.sh"]
