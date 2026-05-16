"""Shared helpers: paths, clipboard, timing, constants."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path


APP_NAME = "FortKey"
APP_DIR = Path.home() / ".fortkey"
DB_FILENAME = "vault.db"


def app_data_dir() -> Path:
    """Directory for DB and local files (created on demand)."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    return APP_DIR


def database_path() -> Path:
    return app_data_dir() / DB_FILENAME


def clear_clipboard() -> None:
    """Best-effort clipboard clear (cross-platform)."""
    try:
        if platform.system() == "Darwin":
            os.system("pbcopy < /dev/null 2>/dev/null")
        elif platform.system() == "Windows":
            import subprocess

            subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Set-Clipboard -Value $null"],
                capture_output=True,
                timeout=5,
            )
        else:
            import subprocess as sp

            for cmd in (["xclip", "-selection", "clipboard"], ["xsel", "-bc"]):
                try:
                    sp.run(cmd, input=b"", capture_output=True, timeout=3)
                    break
                except Exception:
                    continue
    except Exception:
        pass


def resource_path(relative: str) -> Path:
    """Base path for bundled resources (PyInstaller-friendly)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / relative  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent / relative
