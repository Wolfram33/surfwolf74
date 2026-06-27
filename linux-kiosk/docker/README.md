# SurfWolf74 im Docker-Container testen

Startet SurfWolf74 unter Linux (Debian-System-QtWebEngine **inkl. H.264**) und
stellt das GUI per **noVNC im Web** bereit – kein X-Server, kein VNC-Client
nötig. Ideal, um den Linux-Betrieb inkl. X-Video-Wiedergabe zu testen.

## 1. Image bauen (aus dem Projekt-Root)

```bash
docker build -f linux-kiosk/docker/Dockerfile -t surfwolf74-test .
```

## 2. Container starten

```bash
docker run --rm -p 8090:8080 surfwolf74-test
```

> Port: links der Host-Port, rechts der Container-Port (8080). Ist 8090 belegt,
> einfach eine andere freie Zahl nehmen, z. B. `-p 9000:8080`.

## 3. Im Webbrowser öffnen

    http://localhost:8090/vnc.html

Dann auf **Connect** klicken – SurfWolf74 erscheint im Browserfenster und ist
mit Maus/Tastatur bedienbar.

## Optionen

- **Vollbild-/Kiosk-Modus** (statt normalem Fenster):
  ```bash
  docker run --rm -p 8090:8080 -e KIOSK=1 surfwolf74-test
  ```
- **Beenden:** Im Terminal `Strg+C` (Container läuft mit `--rm`, räumt sich auf).

## Hinweise

- **Ton:** Der Container hat kein Audio konfiguriert – Videos laufen visuell,
  aber ohne Ton. Für einen reinen Funktions-/Codec-Test genügt das.
- **X-Videos:** Da hier Debians System-QtWebEngine mit H.264 verwendet wird,
  sollten Videos von x.com hier – anders als unter Windows – abspielen.
- Dies ist ein **Test-Container** (VNC ohne Passwort, nur für lokal gedacht),
  kein gehärtetes Produktiv-Image.
