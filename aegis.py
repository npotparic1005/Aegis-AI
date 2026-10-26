#!/usr/bin/env python3
"""Run Aegis-AI without activating its virtual environment.

  python3 aegis.py scope
  python3 aegis.py scan --objective "Map services on 127.0.0.1"
  python3 aegis.py report --session 1
  python3 aegis.py lab up -d --wait
  python3 aegis.py lab ps
  python3 aegis.py lab down

`lab` forwards arguments
to Docker Compose. See nai/RUNNING.md for setup and baseline instructions.
"""

from pathlib import Path
import os
import shutil
import subprocess
import sys


APP_DIR = Path(__file__).resolve().parent / "nai"


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    if args[0] == "lab":
        docker = shutil.which("docker")
        if not docker:
            print("Docker was not found. Install/start Docker Desktop and reopen your terminal.",
                  file=sys.stderr)
            return 1
        command = [docker, "compose", "--project-name", "aegis-recon",
                   "--file", str(APP_DIR / "compose.yaml"), *(args[1:] or ["ps"])]
    else:
        python = APP_DIR / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        if not python.is_file():
            print("Missing nai/.venv. Follow the one-time setup in nai/RUNNING.md.",
                  file=sys.stderr)
            return 1
        command = [str(python), "-u", "-m", "app.main", *args]

    try:
        # Keep the database, audit log and reports under nai/ regardless
        # of the caller's working directory. Preserve interactive input.
        return subprocess.call(command, cwd=APP_DIR,
                               env={**os.environ, "PYTHONUTF8": "1"})
    except OSError as exc:
        print(f"Could not start the command: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
