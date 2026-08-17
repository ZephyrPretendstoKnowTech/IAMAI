#!/usr/bin/env bash
# IAMAI installer for macOS and Linux.
#
# One command, no prior knowledge required:
#
#   curl -fsSL https://raw.githubusercontent.com/ZephyrPretendstoKnowTech/IAMAI/master/scripts/install.sh | bash
#
# Installs IAMAI into its own isolated virtual environment (so nothing clutters
# your system Python and nothing is installed system-wide), links the `iamai`
# command onto your PATH, verifies the installed command actually answers, and
# starts the guided setup. Current user only, no sudo. IAMAI is read-only: it
# can never change a tenant.
#
# The install source is a plain archive or wheel download, never git+https:
# a machine without git can install this. The preferred source is the pinned
# wheel attached to the latest release, then the release source archive, then
# the master archive as the development fallback.
#
# A dedicated venv is used deliberately: recent macOS (Homebrew) and Linux
# distributions block installing into the system Python (PEP 668), so a venv is
# both the safe and the reliable way to do this without special flags.
set -euo pipefail

# The whole script is a function called on the last line, so a download cut
# off mid-transfer defines half a function and executes nothing, rather than
# running whatever statements happened to arrive intact.
main() {

REPO="ZephyrPretendstoKnowTech/IAMAI"
INSTALL_DIR="${IAMAI_INSTALL_DIR:-$HOME/.iamai}"
VENV="$INSTALL_DIR/venv"
BIN_DIR="$HOME/.local/bin"

say()  { printf '  \033[36m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m%s\033[0m\n' "$1"; }
warn() { printf '  \033[33m%s\033[0m\n' "$1"; }
fail() {
  printf '\n  \033[31mINSTALL FAILED: %s\033[0m\n' "$1"; shift
  for h in "$@"; do warn "$h"; done
  echo
  exit 1
}

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
  fail "Python 3.12 or newer was not found." \
    "Install it, then run this again:" \
    "  macOS:  brew install python@3.12" \
    "  Debian/Ubuntu:  sudo apt install python3.12 python3.12-venv" \
    "  Fedora:  sudo dnf install python3.12"
fi
ok "Python found: $PY"

# --- 2. Pick the install source (pinned release preferred, no git needed) ------
SPEC="https://github.com/$REPO/archive/refs/heads/master.zip"
LABEL="the latest development version (master archive)"
RELEASE_JSON="$(curl -fsSL --max-time 15 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true)"
if [ -n "$RELEASE_JSON" ]; then
  RESOLVED="$(printf '%s' "$RELEASE_JSON" | "$PY" -c '
import json, sys
try:
    release = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
tag = release.get("tag_name") or ""
for asset in release.get("assets") or []:
    name = str(asset.get("name") or "")
    if name.startswith("iamai-") and name.endswith(".whl"):
        print(asset.get("browser_download_url"))
        print(f"release {tag} (pinned wheel)")
        raise SystemExit(0)
if tag:
    print(f"https://github.com/'"$REPO"'/archive/refs/tags/{tag}.zip")
    print(f"release {tag} (source archive)")
' || true)"
  if [ -n "$RESOLVED" ]; then
    SPEC="$(printf '%s\n' "$RESOLVED" | sed -n 1p)"
    LABEL="$(printf '%s\n' "$RESOLVED" | sed -n 2p)"
  fi
else
  warn "Could not look up the latest release; using the development version instead."
fi

# --- 3. Create an isolated environment and install IAMAI into it --------------
say "Installing IAMAI ($LABEL) into its own environment at $VENV ..."
mkdir -p "$INSTALL_DIR"
"$PY" -m venv "$VENV" || fail "Python could not create a virtual environment at $VENV." \
  "On Debian/Ubuntu this usually means the venv module is missing:" \
  "  sudo apt install python3.12-venv" \
  "then run this installer again."
# From here on use the venv's own python/pip: it is isolated, so no PEP 668
# block and no --user or --break-system-packages needed.
"$VENV/bin/python" -m pip install --quiet --upgrade pip || fail \
  "pip could not upgrade itself inside the new environment." \
  "If this machine uses a proxy, configure it for pip and run the installer again."
"$VENV/bin/python" -m pip install --quiet "$SPEC" || fail \
  "pip could not install IAMAI from $LABEL." \
  "The lines above are pip's own report of what went wrong." \
  "If it mentions a network or proxy problem, fix that and run the installer again."

# --- 4. Verify before claiming anything, then link the command onto PATH -------
if ! "$VENV/bin/iamai" --version >/dev/null 2>&1; then
  # Releases before 1.3.0 have no --version; --help proves the command runs.
  "$VENV/bin/iamai" --help >/dev/null 2>&1 || fail \
    "IAMAI was installed but its command does not run." \
    "Run  $VENV/bin/iamai --help  to see its error, and copy it into an issue:" \
    "  https://github.com/$REPO/issues"
fi
mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/iamai" "$BIN_DIR/iamai"
ok "IAMAI is installed and verified. The 'iamai' command is linked in $BIN_DIR."

case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;  # already on PATH
  *)
    warn "$BIN_DIR is not on your PATH. Add this line to your shell profile"
    warn "(~/.zshrc on macOS, ~/.bashrc on Linux), then open a new terminal:"
    warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    ;;
esac

# --- 5. Start the guided setup (call the venv directly, PATH-independent) ------
echo
say "Starting setup. It will walk you through connecting a tenant."
echo
"$VENV/bin/iamai" setup

}

main "$@"
