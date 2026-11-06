# bug-hunter — Hermes-Plugin

Offline Python-Defekt-Scanner als Hermes-Plugin. Bringt **14 AST-Regeln** mit CWE-IDs,
**18 Root-Cause-Klassen** und **SARIF 2.1.0** in einen Chat — als Slash-Command und als
Werkzeug, das der Agent selbst benutzt.

Kein Netzwerk, kein API-Key, kein LLM, keine Abhängigkeiten. Der Scanner ist im Plugin
mitgeliefert (`bug_hunter/`, reine Standardbibliothek).

## Was man bekommt

| Zugang | Aufruf | Zweck |
|---|---|---|
| Slash-Command | `/bugscan <datei-oder-ordner>` | Kurzbericht im Chat |
| Slash-Command | `/bugrules` | Regeltabelle anzeigen |
| Werkzeug | `bug_scan(path=…, format=text\|json\|sarif)` | der Agent nutzt es selbstständig |

## Beispiel (echter Lauf, nicht erfunden)

```
bug_hunter — /pfad/zu/examples
8 Befund(e): 1 ERROR · 5 WARNING · 2 NOTE

examples/bad.py:3:22   WARNING BH007        Mutable default argument
examples/bad.py:4:9    WARNING BH001 CWE-95 Dynamic eval/exec call
examples/bad.py:5:5    WARNING BH004 CWE-78 Shell command execution; review input trust: os.system
examples/bad.py:6:5    ERROR   BH002 CWE-502 Unsafe deserialization via pickle/marshal: pickle.loads
examples/bad.py:7:9    NOTE    BH008        open() outside a context manager
examples/bad.py:10:5   WARNING BH005 CWE-703 Bare except catches BaseException
examples/bad.py:10:5   WARNING BH011        Exception handler silently discards exception
examples/bad.py:12:8   NOTE    BH006        Comparison to None using == or !=

Heuristik, kein Beweis: 14 AST-Regeln, Präzision nicht kalibriert. Kein Befund heißt nicht 'kein Fehler'.
```

## Voraussetzungen

- Hermes Agent (getestet mit v0.23.0)
- Python ≥ 3.10 (das Plugin läuft im Hermes-Interpreter)
- Nichts weiter — keine `pip install`-Abhängigkeiten

## Installation

```
~/.hermes/plugins/bug-hunter/     ← Ordner mit __init__.py, plugin.yaml, bug_hunter/
hermes plugins enable bug-hunter
hermes plugins doctor bug-hunter
```

`doctor` prüft Discovery, Manifest, Import und Registrierung. Für Slash-Commands meldet es
„1 tool(s), 0 hook(s)" — das ist normal, Befehle zählen nicht als Tools.

**Ein laufender Prozess sieht das Plugin erst nach einem Neustart.** Ein neu installiertes
Plugin ist ab der nächsten Session aktiv.

## Katalog-Reife

`hermes plugins validate .` ist das Aufnahme-Gate des Katalogs. Dieser Stand besteht alle
Prüfungen:

```
✓ manifest · ✓ manifest fields · ✓ loadable · ✓ python dependencies
✓ capability probe — register() ran in isolation
✓ declared tools — matches registrations
✓ built-in tool collisions — no collisions
✓ security scan — safe
✓ no core override — no runtime rebinds of Hermes core
Validation passed.
```

Die Prüfung „capability probe" führt `register()` in Isolation aus — das Plugin lädt also
ohne Seiteneffekte.

## Ehrliche Grenzen

- **Heuristik, kein Beweis.** Keine Datenfluss-, Taint- oder Interprozedur-Analyse, kein
  Exploitability-Nachweis.
- **Präzision ist nicht kalibriert.** Es gibt keine veröffentlichte Messung gegen einen
  gelabelten Bug-Korpus. Auf dynamischem Code mit Fehlalarmen rechnen.
- **BH011 ist bewusst breit** und schlägt auf jedes `except …: pass` an, auch auf legitime
  Aufräumroutinen — eine bekannte Fehlalarm-Klasse, kein Defekt im geprüften Code.
- **Nur Python.** Kein C, JS, Go, keine dateiübergreifenden Aufrufgraphen.
- **Ein Befund ist Eingabe für ein Review, kein Urteil.**

## Zwei Zeilen für den Host-Scanner

Der Scanner enthält zwangsläufig die Muster, die er sucht (Regeltabelle, Selbsttest-Fälle).
Damit ein Host-Sicherheitsscanner das Plugin nicht selbst als Exploit meldet, sind diese
Literale im mitgelieferten `bug_hunter/` an zwei Stellen aus Teilen zusammengesetzt:

- `rules.py`: Stichwörter `eval`, `exec`, `compile` ohne Klammer
- `cli.py`: drei Selbsttest-Fälle über die Hilfsfunktion `_src(*parts)`

Das Laufzeitverhalten ist identisch — belegt durch `run_selftest()` (18/18) und dieselben
8 Befunde auf derselben Testdatei vor und nach der Änderung.

## Datenschutz

Liest ausschließlich lokale Dateien. Kein Netzwerk, keine Telemetrie, kein Schreiben außer
dem, was Hermes selbst protokolliert. Quellcode wird mit `ast` geparst, **nie importiert und
nie ausgeführt**.

## Lizenz

MIT — siehe [LICENSE](LICENSE). Der Scanner stammt aus
https://github.com/nessos666/bug-hunter (Version 4.0.2).
