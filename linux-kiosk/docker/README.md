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

    http://localhost:8090/

Verbindet automatisch und **skaliert auf dein Fenster** (kein kleiner Rahmen).
SurfWolf74 ist sofort mit Maus/Tastatur bedienbar.

> Falls du die alte Ansicht willst: `http://localhost:8090/vnc.html`. Wirkt das
> Bild dort klein, im Zahnrad-Menü **Scaling Mode → Local Scaling** wählen –
> oder direkt `…/vnc.html?autoconnect=true&resize=scale` öffnen.

## Optionen

- **Auflösung** des virtuellen Bildschirms anpassen (Standard 1920x1080):
  ```bash
  docker run --rm -p 8090:8080 -e SCREEN=1600x900 surfwolf74-test
  ```
- **Fenster-Modus** statt Vollbild (Vollbild ist Standard):
  ```bash
  docker run --rm -p 8090:8080 -e KIOSK=0 surfwolf74-test
  ```
  Hinweis: Im Container kann das normale Fenster wegen des Maximier-Timings
  versetzt rendern – fürs Testen ist daher der Vollbild-Standard empfohlen.
- **Beenden:** Im Terminal `Strg+C` (Container läuft mit `--rm`, räumt sich auf).

## Hinweise

- **Ton:** Der Container hat kein Audio konfiguriert – Videos laufen visuell,
  aber ohne Ton. Für einen reinen Funktions-/Codec-Test genügt das.
- **Codecs funktionieren:** Verifiziert spielen lokale H.264- **und** VP9-Dateien
  im Container vollständig ab (Decode + Darstellung). Das war die Kernfrage.
- Dies ist ein **Test-Container** (VNC ohne Passwort, nur für lokal gedacht),
  kein gehärtetes Produktiv-Image.

## Bekannte Grenzen (wichtig für Video)

Der Container ist **headless ohne echte GPU** (Software-Rendering im Xvfb). Das
reicht für die Oberfläche und einfaches Video, aber **nicht** für YouTube:

- **YouTube spielt im Container nicht** – sein „SABR"-Streaming wird per CORS
  blockiert bzw. stockt. Getestet und reproduziert mit Chromium 108 (Debian
  bookworm) **und** Chromium ~122 (Debian trixie); auch SwiftShader-GL half
  nicht. Es liegt also nicht an der Browser-Version, sondern an der fehlenden
  echten GPU/Composition im Headless-Container.
- Auf **echter Hardware** (Linux-Desktop mit GPU) verhält sich der Browser wie
  unter Windows, wo YouTube läuft. Für ein finales Urteil zu YouTube/x.com
  daher auf einem echten Linux-Desktop oder einer Desktop-VM testen, nicht im
  headless Container.

Kurz: Der Container beweist „App läuft + Codecs/Decode funktionieren". Das echte
Streaming-Verhalten anspruchsvoller Seiten gehört auf echte Hardware getestet.
