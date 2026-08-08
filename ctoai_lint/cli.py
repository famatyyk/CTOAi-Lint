"""ctoai-lint — lekki, darmowy linter C++ / Lua / Python.

Samodzielny pakiet (stdlib only, bez zaleznosci). Wykrywa podstawowe
ryzyka statyczne i liczy "health" 0-100. Pelna wersja (Project Doctor)
jest platna: https://ctoai-funnel.fly.dev/

Legalne: read-only analiza plikow tekstowych.
"""
from __future__ import annotations
import argparse, os, re, sys
from pathlib import Path

CXX_UNSAFE = re.compile(r'\b(strcpy|strcat|gets|sprintf|scanf)\s*\(')
LUA_DYN = re.compile(r'\b(load|loadstring|os\.execute|os\.execute|io\.popen)\b')
PY_EXEC = re.compile(r'\b(eval|exec|os\.system|subprocess\.call|pickle\.loads)\b')
SECRET = re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\'"]')

EXT_MAP = {
    ".cpp": "cxx", ".cc": "cxx", ".cxx": "cxx", ".c": "cxx", ".h": "cxx", ".hpp": "cxx",
    ".lua": "lua",
    ".py": "py",
}


def scan_file(path: Path) -> list[dict]:
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings
    kind = EXT_MAP.get(path.suffix.lower())
    if kind == "cxx":
        for i, line in enumerate(text.splitlines(), 1):
            if CXX_UNSAFE.search(line):
                findings.append({"sev": "high", "rule": "cxx.unsafe-func",
                                 "line": i, "msg": "Niebezpieczna funkcja C (strcpy/strcat/gets/sprintf/scanf)"})
    elif kind == "lua":
        for i, line in enumerate(text.splitlines(), 1):
            if LUA_DYN.search(line):
                findings.append({"sev": "high", "rule": "lua.dyn",
                                 "line": i, "msg": "Dynamiczne wykonanie (load/os.execute/io.popen)"})
    elif kind == "py":
        for i, line in enumerate(text.splitlines(), 1):
            if PY_EXEC.search(line):
                findings.append({"sev": "medium", "rule": "py.exec",
                                 "line": i, "msg": "eval/exec/os.system (ryzyko)"})
    if SECRET.search(text):
        findings.append({"sev": "high", "rule": "secret.leak", "line": 0,
                         "msg": "Podejrzana przypisanie sekretu w kodzie"})
    return findings


def audit(target: str) -> dict:
    root = Path(target)
    if not root.exists():
        return {"error": f"sciezka nie istnieje: {target}"}
    files, findings = [], []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in EXT_MAP:
            files.append(p)
            findings.extend(scan_file(p))
    high = sum(1 for f in findings if f["sev"] == "high")
    # health: start 100, -8 za high, -3 za medium, min 0
    med = sum(1 for f in findings if f["sev"] == "medium")
    health = max(0, 100 - high * 8 - med * 3)
    return {"target": str(root), "files": len(files), "findings": len(findings),
            "high": high, "health": health}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ctoai-lint", description="Lekki linter C++/Lua/Python (darmowy).")
    ap.add_argument("target", nargs="?", default=".", help="Sciezka do analizy (domyslnie .)")
    ap.add_argument("--json", action="store_true", help="Wyjscie JSON")
    args = ap.parse_args(argv)
    res = audit(args.target)
    if "error" in res:
        print(res["error"], file=sys.stderr); return 2
    if args.json:
        print(__import__("json").dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"ctoai-lint: {res['files']} plikow, {res['findings']} znalezisk, HIGH={res['high']}")
        print(f"Project Health: {res['health']}/100")
        if res["health"] < 100:
            print("Pelny raport + 5 krokow naprawczych: https://ctoai-funnel.fly.dev/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
