# SurfWolf74 als Linux-Kiosk-Appliance

Ziel: Ein PC bootet direkt in SurfWolf74 — kein Desktop, keine Taskleiste,
nur der Browser im Vollbild. Auf einem **Debian**-Unterbau spielt der Browser
zusätzlich **X-Videos (H.264)** ab, was unter Windows nicht geht.

> `surfwolf74.py` im Projekt-Root bleibt **unverändert**. Dieses Verzeichnis
> enthält nur die zusätzliche Linux-/Kiosk-Schicht; sie lädt den Browser und
> erzwingt den Vollbild-Modus zur Laufzeit (Monkeypatch), ohne den Code zu ändern.

## Warum Debian (wichtig!)
Die H.264/AAC-Codecs (für X-Videos) stecken **nur** in Debians
System-Paket `python3-pyqt6.qtwebengine` — **nicht** in den pip-Wheels und
**nicht** in einem Nuitka-Build, der das pip-Wheel bündelt. Per Docker verifiziert:

| Variante | H.264 / X-Videos |
|---|---|
| pip `PyQt6-WebEngine` (Win + Linux) | ❌ |
| Debian `python3-pyqt6.qtwebengine` | ✅ |

Die Appliance läuft den Browser daher als **normales Python-Skript** gegen die
System-Pakete — kein Nuitka nötig.

## Schnellstart auf einem bestehenden Debian (Test in VM oder altem PC)
```sh
# 1. Abhängigkeiten installieren (System-Qt mit Codecs + minimaler X-Server)
./install-debian.sh

# 2. Browser im Vollbild starten (in einer laufenden X-Sitzung)
./kiosk.py
```

## Echte Appliance: beim Booten direkt in den Browser
1. Debian **minimal** installieren (netinst, ohne Desktop-Umgebung).
2. `./install-debian.sh` ausführen.
3. **Autologin** auf der Textkonsole einrichten (tty1), z. B. per
   `sudo systemctl edit getty@tty1` mit:
   ```
   [Service]
   ExecStart=
   ExecStart=-/sbin/agetty --autologin DEIN_USER --noclear %I $TERM
   ```
4. In `~/.bash_profile` des Users beim Login automatisch X starten:
   ```sh
   if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
       exec startx "$(pwd)/start-kiosk.sh"
   fi
   ```
   (Pfad ggf. absolut auf dieses Verzeichnis setzen.)
5. `start-kiosk.sh` startet den Browser im Vollbild und in einer
   **Neustart-Schleife** (Absturz → automatischer Neustart).

## Dateien
- `install-debian.sh` — installiert System-Qt (mit Codecs), X-Server, Xterm-frei.
- `kiosk.py` — lädt `../surfwolf74.py` und erzwingt Vollbild (ändert die Datei nicht).
- `start-kiosk.sh` — X-Sitzungs-Einstieg: Energiesparen aus + Browser in Restart-Schleife.

## Stand der Verifikation (ehrlich)
- ✅ Per Docker getestet: Code importiert unter Linux, Debian-Qt spielt H.264.
- ⚠️ **Noch nicht** auf echter Hardware/VM als kompletter Boot-zu-Kiosk getestet.
  Schritte 3–5 sind Standard-Kiosk-Praxis, aber bitte zuerst in einer VM prüfen.

## Bekannte Punkte / Härtung (später)
- Config/Bookmarks liegen relativ zu `surfwolf74.py`; für eine reine Appliance
  ggf. auf einen beschreibbaren Pfad umlenken (sonst Root-FS beschreibbar halten).
- TTY-Wechsel (Strg+Alt+F2) und X-Shortcuts ggf. sperren.
- WLAN-/GPU-Treiber sind die üblichen Linux-Baustellen (Hardware-abhängig).
