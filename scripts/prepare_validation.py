#!/usr/bin/env python3
"""Prepare a private, offline validation workspace; never run a scan or load credentials."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from mendpact.validation_setup import prepare_workspace

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label", help="Unique local run label, e.g. 2026-09-07-server-a")
    arguments = parser.parse_args()
    try:
        destination = prepare_workspace(ROOT, arguments.label)
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(
            2,
            "Could not prepare workspace. Activate the project environment and install it with "
            "`python -m pip install -e '.[dev]'`, then check the label, paths, and Git checkout. "
            "Existing files were not replaced; inspect any partial new directory.\n",
        )
    print(
        f"Prepared {destination}\nNo validation has run. Complete authorization.json, then "
        "follow docs/REAL_WORLD_VALIDATION.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
