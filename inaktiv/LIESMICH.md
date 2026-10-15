# inaktiv/ – nicht betriebsnotwendig

Alles hier wird zum Starten, Bauen oder Ausliefern von SurfWolf74 **nicht**
gebraucht. Der Windows-Build (Nuitka/Inno Setup) und das Linux-Paket greifen
nicht auf diesen Ordner zu.

| Pfad | Inhalt |
|------|--------|
| `tests/test_homograph.py` | Tests für den Schutz vor gefälschten Adressen (Homograph-Angriffe). Aufruf aus dem Projektordner: `.venv\Scripts\python.exe -X utf8 inaktiv\tests\test_homograph.py` |

Bewusst am Platz geblieben (betriebs- oder build-notwendig): `windows-build/`,
`linux-kiosk/`, `.github/`, `kombilieren.txt` (Build-Befehl), die JSON-Startdateien
und Bilder im Projektordner.
