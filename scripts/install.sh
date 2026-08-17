#!/usr/bin/env bash
# IAMAI installer for macOS and Linux.
#
# One command, no prior knowledge required:
#
#   curl -fsSL https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.sh | bash
#
# Installs IAMAI into its own isolated virtual environment (so nothing clutters
# your system Python and nothing is installed system-wide), links the `iamai`
# command onto your PATH, and starts the guided setup. Current user only, no
# sudo. IAMAI is read-only: it can never change a tenant.
#
# A dedicated venv is used deliberately: recent macOS (Homebrew) and Linux
# distributions block installing into the system Python (PEP 668), so a venv is
# both the safe and the reliable way to do this without special flags.
set -euo pipefail

# The whole script is a function called on the last line, so a download cut
# off mid-transfer defines half a function and executes nothing, rather than
# running whatever statements happened to arrive intact.
main() {

REPO_URL="https://github.com/ZephyrPretendstoKnowTech/IAMAI.git"
INSTALL_DIR="${IAMAI_INSTALL_DIR:-$HOME/.iamai}"
VENV="$INSTALL_DIR/venv"
BIN_DIR="$HOME/.local/bin"

say()  { printf '  \033[36m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m%s\033[0m\n' "$1"; }
warn() { printf '  \033[33m%s\033[0m\n' "$1"; }

echo
echo "IAMAI installer"
echo "Read-only Microsoft Entra identity posture. Installs for you only, no sudo."
echo

# --- 1. Find a Python 3.12+ interpreter ---------------------------------------
PY=""
for cand in python3.13 python3.12 python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 12) else 1)' 2>/dev/null; then
      PY="$(command -v "$cand")"; break
    fi
  fi
done

if [ -z "$PY" ]; then
  warn "Python 3.12 or newer was not found."
  warn "Install it, then run this again:"
  warn "  macOS:  brew install python@3.12"
  warn "  Debian/Ubuntu:  sudo apt install python3.12 python3.12-venv"
  warn "  Fedora:  sudo dnf install python3.12"
  exit 1
fi
ok "Python found: $PY"

# --- 2. Create an isolated environment and install IAMAI into it --------------
say "Installing IAMAI into its own environment at $VENV ..."
mkdir -p "$INSTALL_DIR"
"$PY" -m venv "$VENV"
# From here on use the venv's own python/pip: it is isolated, so no PEP 668
# block and no --user or --break-system-packages needed.
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet "git+$REPO_URL"

# --- 3. Link the command onto PATH --------------------------------------------
mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/iamai" "$BIN_DIR/iamai"
ok "IAMAI is installed. The 'iamai' command is linked in $BIN_DIR."

case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;  # already on PATH
  *)
    warn "$BIN_DIR is not on your PATH. Add this line to your shell profile"
    warn "(~/.zshrc on macOS, ~/.bashrc on Linux), then open a new terminal:"
    warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    ;;
esac

# --- 4. Start the guided setup (call the venv directly, PATH-independent) ------
echo
say "Starting setup. It will walk you through connecting a tenant."
echo
"$VENV/bin/iamai" setup

}

main "$@"
