#!/bin/sh
# Baut ein natives .deb-Paket fuer SurfWolf74.
#
# Kanonische Quelle ist surfwolf74.py im Projekt-Root. Existiert dieser, wird
# die lokale Kopie in linux-kiosk/ vor dem Build automatisch aktualisiert
# ("alles zusammen", aber ohne Drift). Fehlt der Root (eigenstaendig verteiltes
# linux-kiosk), wird die lokale Kopie verwendet.
#
# Version wird aus APP_VERSION in surfwolf74.py gelesen (eine Quelle der Wahrheit).
# Ergebnis: linux-kiosk/surfwolf74_<version>_all.deb
# Voraussetzung: auf Debian/Ubuntu ausfuehren (braucht dpkg-deb).
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$(cd "$HERE/.." && pwd)"           # linux-kiosk/
ROOT="$(cd "$HERE/../.." && pwd)"          # Projekt-Root

# App-Quelle bestimmen und lokale Kopie synchron halten
if [ -f "$ROOT/surfwolf74.py" ]; then
    APPDIR="$ROOT"
    cp -f "$ROOT/surfwolf74.py" "$OUTDIR/surfwolf74.py"   # Kopie aktuell halten
else
    APPDIR="$OUTDIR"
fi

VERSION="$(grep -oP 'APP_VERSION\s*=\s*"\K[^"]+' "$APPDIR/surfwolf74.py" 2>/dev/null || true)"
[ -n "$VERSION" ] || VERSION="0.0"

STAGE="$(mktemp -d)"
PKG="$STAGE/surfwolf74"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$PKG/DEBIAN" \
         "$PKG/usr/lib/surfwolf74" \
         "$PKG/usr/bin" \
         "$PKG/usr/share/applications" \
         "$PKG/usr/share/pixmaps"

# --- App + Assets ---
cp "$APPDIR/surfwolf74.py" "$PKG/usr/lib/surfwolf74/"
for f in surfwolf74.png icon.ico icon.png folder.png bookmarks.json config.json blocked_sites.json; do
    [ -f "$APPDIR/$f" ] && cp "$APPDIR/$f" "$PKG/usr/lib/surfwolf74/" || true
done

# --- Launcher, Desktop-Eintrag, Icon ---
# Launcher mit garantierten LF-Zeilenenden schreiben (Shebang-Sicherheit, auch
# falls die Quelle unter Windows mit CRLF ausgecheckt wurde).
sed 's/\r$//' "$HERE/surfwolf74" > "$PKG/usr/bin/surfwolf74"
install -m 0644 "$HERE/surfwolf74.desktop" "$PKG/usr/share/applications/surfwolf74.desktop"
[ -f "$APPDIR/icon.png" ] && cp "$APPDIR/icon.png" "$PKG/usr/share/pixmaps/surfwolf74.png" || true

# --- Dateirechte normalisieren (Windows-Mounts liefern oft 0755) ---
find "$PKG/usr/lib/surfwolf74" -type f -exec chmod 0644 {} +
chmod 0644 "$PKG/usr/share/applications/surfwolf74.desktop"
[ -f "$PKG/usr/share/pixmaps/surfwolf74.png" ] && chmod 0644 "$PKG/usr/share/pixmaps/surfwolf74.png"
chmod 0755 "$PKG/usr/bin/surfwolf74"

# --- Steuerdatei mit Version ---
sed "s/@VERSION@/$VERSION/" "$HERE/control" > "$PKG/DEBIAN/control"

# --- Bauen ---
OUT="$OUTDIR/surfwolf74_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$PKG" "$OUT"

echo ""
echo "Gebaut: $OUT"
echo "Installieren (mit Abhaengigkeitsaufloesung):"
echo "    sudo apt install $OUT"
