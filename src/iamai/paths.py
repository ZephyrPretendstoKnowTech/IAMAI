"""Where IAMAI keeps its files.

A professional app does not scatter data, certificates and config into whatever
directory it happened to be launched from. Everything lives in one per-user
location, resolved the same way every OS expects:

  Windows   %LOCALAPPDATA%\\IAMAI
  macOS     ~/Library/Application Support/IAMAI
  Linux     ~/.local/share/iamai   (or $XDG_DATA_HOME/iamai)

Set the IAMAI_HOME environment variable to override it (power users, or a
locked-down machine that wants everything on one drive). The test suite sets it
per test so nothing ever touches the real location.

Paths are resolved lazily, at call time, not imported as constants, so the
override is read after the process starts rather than frozen at import.
"""

from __future__ import annotations

import os
from pathlib import Path

_APP_NAME = "IAMAI"


def app_home() -> Path:
    """The one directory that holds everything for this user."""
    override = os.environ.get("IAMAI_HOME")
    if override:
        return Path(override).expanduser()
    from platformdirs import user_data_dir

    # appauthor=False keeps the path a single "IAMAI" folder rather than
    # nesting it under a company directory nobody would recognise.
    return Path(user_data_dir(_APP_NAME, appauthor=False))


def data_dir() -> Path:
    """Collected snapshots, assessments and plans."""
    return app_home() / "data"


def config_path() -> Path:
    """The single config file written by `iamai setup`."""
    return app_home() / "config.yaml"


def cert_dir() -> Path:
    """The certificate the tool authenticates with."""
    return app_home() / "certs"
