#!/usr/bin/env bash
# IAMAI installer for macOS and Linux.
#
# One command, no prior knowledge required:
#
#   curl -fsSL https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.sh | bash
#
# It finds Python, installs IAMAI into its own isolated place so it never
# clutters anything, adds the `iamai` command to your PATH, and starts the
# guided setup. Installs for the current user only; no sudo. IAMAI is read-only:
# it can never change a tenant.
set -euo pipefail

REPO_URL="https://github.com/ZephyrPretendstoKnowTech/IAMAI.git"
say()  { printf '  \033[36m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m%s\033[0m\n' "$1"; }
warn() { printf '  \033[33m%s\033[0m\n' "$1"; }

echo
echo "IAMAI installer"
echo "Read-only Microsoft Entra identity posture. Installs for you only."
echo

# --- 1. Find a Python 3.12+ interpreter ---------------------------------------
PY=""
for cand in python3.13 python3.12 python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,12) else 1)' 2>/dev/null; then
      PY="$cand"; break
    fi
  fi
done

if [ -z "$PY" ]; then
  warn "Python 3.12 or newer was not found."
  warn "Install it (macOS: 'brew install python@3.12'; Linux: your package manager),"
  warn "then run this installer again."
  exit 1
fi
ok "Python found: $PY"

# --- 2. Ensure pipx (isolated app installer) ----------------------------------
say "Preparing the installer..."
if ! command -v pipx >/dev/null 2>&1; then
  "$PY" -m pip install --user --quiet --upgrade pip pipx
fi
"$PY" -m pipx ensurepath >/dev/null 2>&1 || true
# Put pipx's app directory on PATH for THIS session.
PIPX_BIN="$("$PY" -m pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")"
export PATH="$PIPX_BIN:$PATH"

# --- 3. Install IAMAI from GitHub ---------------------------------------------
say "Installing IAMAI..."
"$PY" -m pipx install --force "git+$REPO_URL"

if ! command -v iamai >/dev/null 2>&1; then
  ok "IAMAI is installed."
  warn "Open a new terminal, then run:  iamai setup"
  exit 0
fi

# --- 4. Start the guided setup ------------------------------------------------
ok "IAMAI is installed."
echo
say "Starting setup. It will walk you through connecting a tenant."
echo
iamai setup
