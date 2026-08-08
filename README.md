# CTOAi-Lint

[![Self-Lint](https://github.com/famatyyk/CTOAi-Lint/actions/workflows/lint.yml/badge.svg)](https://github.com/famatyyk/CTOAi-Lint/actions)

Darmowy, lekki linter **C++ / Lua / Python** — statyczna analiza read-only.
Demo silnika za [CTOAi Project Doctor](https://ctoai-funnel.fly.dev/).

## Instalacja
```bash
pip install ctoai-lint
```

## Użycie
```bash
ctoai-lint .                 # audyt biezacego katalogu
ctoai-lint src/ --json      # wyjscie JSON
```

## Co wykrywa
- **C/C++**: `strcpy`, `strcat`, `gets`, `sprintf`, `scanf` (high)
- **Lua**: `load`, `loadstring`, `os.execute`, `io.popen` (high)
- **Python**: `eval`, `exec`, `os.system`, `subprocess.call`, `pickle.loads` (medium)
- **Sekrety**: podejrzane przypisania `api_key=...`, `password=...` (high)

## Project Health
`health = 100 - 8*high - 3*medium` (min 0).

## Legalne
Tylko analiza plikow tekstowych. Brak modyfikacji kodu, brak injection.

## Pełna wersja (płatna)
Project Doctor: C++, Lua, Python, JS, TS, CMake, 5 kroków naprawczych, GitHub Action (Doctor CI).
https://ctoai-funnel.fly.dev/

MIT — używaj swobodnie.
