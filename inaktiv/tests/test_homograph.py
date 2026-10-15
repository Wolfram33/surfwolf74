r"""Tests für den Homograph-Schutz (vorgetäuschte Adressen) in surfwolf74.py.

Aufruf aus dem Projektordner:
    .venv\Scripts\python.exe -X utf8 inaktiv\tests\test_homograph.py
"""
import importlib.util
import os
import sys

from PyQt6.QtCore import QUrl

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
spec = importlib.util.spec_from_file_location("surfwolf74", os.path.join(ROOT, "surfwolf74.py"))
sw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sw)

# (Host, soll als verdächtig gelten?, Beschreibung)
HOST_CASES = [
    ("amαzon.com", True, "griechisches Alpha in amazon (X-Beitrag)"),
    ("аррӏе.com", True, "komplett kyrillisch nachgebautes apple"),
    ("gооgle.com", True, "kyrillische o in google"),
    ("pаypal.com", True, "kyrillisches a in paypal"),
    ("ɡoogle.com", True, "lateinisches Schreibschrift-g"),
    ("paypaı.com", True, "punktloses i statt l"),
    ("www.еbаy.de", True, "Subdomain unverdächtig, Hauptname gemischt"),
    ("еріс.com", True, "kyrillische Ganz-Schrift-Fälschung unter .com"),
    ("example.com", False, "reines ASCII"),
    ("xn--80ak6aa92e.com", False, "bereits Punycode: kann nicht täuschen"),
    ("müller.de", False, "deutscher Umlaut"),
    ("bücher-straße.de", False, "Umlaut und ß"),
    ("café.fr", False, "französischer Akzent"),
    ("еріс.рф", False, "kyrillisch unter kyrillischer Endung"),
    ("пример.рф", False, "normales kyrillisches Wort"),
    ("日本語.jp", False, "Kanji"),
    ("ひらがなカタカナ漢字.jp", False, "japanische Schriftmischung"),
    ("한국어.kr", False, "Hangul"),
    ("ελληνικά.gr", False, "echtes griechisches Wort"),
    ("", False, "leerer Host"),
]


def run():
    failures = 0
    for host, expected, description in HOST_CASES:
        reason = sw.homograph_reason(host)
        ok = bool(reason) == expected
        failures += not ok
        print(f"{'OK ' if ok else 'FEHLER'} {host!r:32} {description}: {reason}")

    # Anzeige: verdächtige Hosts als Punycode, Benutzername nie sichtbar
    text, reason = sw.url_display_info(QUrl("https://amαzon.com/login"))
    ok = text.startswith("https://xn--") and reason
    failures += not ok
    print(f"{'OK ' if ok else 'FEHLER'} Anzeige verdächtig -> {text}")

    text, reason = sw.url_display_info(QUrl("https://www.amazon.com@betrug.example/x"))
    ok = text == "https://betrug.example/x" and reason
    failures += not ok
    print(f"{'OK ' if ok else 'FEHLER'} Benutzername-Trick -> {text} | {reason}")

    text, reason = sw.url_display_info(QUrl("https://müller.de/über"))
    ok = text == "https://müller.de/über" and reason is None
    failures += not ok
    print(f"{'OK ' if ok else 'FEHLER'} Umlaut-Domain bleibt lesbar -> {text}")

    print(f"\n{len(HOST_CASES) + 3 - failures} bestanden, {failures} fehlgeschlagen")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
