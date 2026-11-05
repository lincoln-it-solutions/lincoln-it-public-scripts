#!/bin/sh
# Install-Homebrew.sh -- install Homebrew from a ROOT script (TRMM) with NO password and NO sudo prompt.
#
# WHY NOT THE OFFICIAL install.sh: read from its source (Homebrew/install): on macOS it runs a sudo check
# unconditionally and aborts ("Need sudo access on macOS") unless the user has passwordless sudo, and it refuses to
# run as root. Neither can be satisfied from an RMM. So we do the part that matters ourselves:
#   1. as ROOT: create the prefix and hand it to the Homebrew owner (root needs no password to do this);
#   2. as the OWNER: git clone the Homebrew/brew repository into it (on Apple Silicon the prefix IS the repository).
# Nothing else is needed for casks; brew creates Caskroom/Cellar on first use.
#
# Usage: Install-Homebrew.sh --owner USER [--prefix DIR] [--remote GIT_URL]
#   --owner   the admin account that will own Homebrew (required; never root)
#   --prefix  default /opt/homebrew (Apple Silicon default prefix). Other prefixes are for TESTING only.
#   --remote  where to clone brew from; default $HOMEBREW_BREW_GIT_REMOTE, else the public Homebrew/brew repo.
#             Point this at our own mirror to stop depending on GitHub (HOMEBREW_BREW_GIT_REMOTE is Homebrew's
#             own name for the same setting).
# Idempotent: if PREFIX/bin/brew already exists it does nothing.
# Exit codes: 0 installed / already there   2 bad usage   3 unsupported machine   4 owner problem
#             5 Command Line Tools missing and could not be installed   6 clone failed
PREFIX=/opt/homebrew; OWNER=; REMOTE="${HOMEBREW_BREW_GIT_REMOTE:-https://github.com/Homebrew/brew}"
while [ $# -gt 0 ]; do case "$1" in
  --owner) OWNER="$2"; shift 2;; --prefix) PREFIX="$2"; shift 2;; --remote) REMOTE="$2"; shift 2;;
  *) echo "unknown argument: $1"; exit 2;; esac; done
[ -n "$OWNER" ] || { echo "ERROR: --owner is required"; exit 2; }

[ "$(uname -s)" = "Darwin" ] || { echo "ERROR: macOS only"; exit 3; }
if [ "$PREFIX" = "/opt/homebrew" ] && [ "$(uname -m)" != "arm64" ]; then echo "ERROR: /opt/homebrew is the Apple Silicon prefix; this Mac is $(uname -m)"; exit 3; fi
[ "$OWNER" != "root" ] && id "$OWNER" >/dev/null 2>&1 || { echo "ERROR: owner '$OWNER' missing or root"; exit 4; }
id -Gn "$OWNER" | tr ' ' '\n' | grep -qx admin || { echo "ERROR: owner '$OWNER' is not an admin"; exit 4; }
[ -x "$PREFIX/bin/brew" ] && { echo "Homebrew already present at $PREFIX - nothing to do."; exit 0; }
# A non-empty prefix that is not Homebrew is not ours to overwrite.
if [ -d "$PREFIX" ] && [ -n "$(ls -A "$PREFIX" 2>/dev/null)" ]; then echo "ERROR: $PREFIX exists, is not empty and has no bin/brew - not touching it."; exit 4; fi

# --- Command Line Tools (git comes from them) ---------------------------------------------------------------
# The same check install.sh makes. If missing and we are root, install them the way install.sh does first:
# ask softwareupdate for the CLT label (the marker file makes it list them). UNTESTED on a Mac without CLT.
if [ ! -x /Library/Developer/CommandLineTools/usr/bin/git ]; then
  if [ "$(id -u)" -ne 0 ]; then echo "ERROR: Command Line Tools missing and not root, cannot install them."; exit 5; fi
  echo "Command Line Tools missing - installing via softwareupdate..."
  touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
  LABEL=$(softwareupdate -l 2>/dev/null | grep -B1 -E "Command Line Tools" | awk -F'*' '/^ *\*/ {print $2}' | sed -e 's/^ *Label: //' -e 's/^ *//' | sort -V | tail -n1)
  [ -n "$LABEL" ] && softwareupdate -i "$LABEL" --verbose
  rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
  [ -x /Library/Developer/CommandLineTools/usr/bin/git ] || { echo "ERROR: Command Line Tools install failed."; exit 5; }
fi
GIT=/Library/Developer/CommandLineTools/usr/bin/git

# --- 1. Prefix, owned by the owner --------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p "$PREFIX" && chown "$OWNER":admin "$PREFIX" && chmod 755 "$PREFIX" || { echo "ERROR: could not create $PREFIX"; exit 4; }
  AS_OWNER() { sudo -H -u "$OWNER" env HOME="$(dscl . -read "/Users/$OWNER" NFSHomeDirectory | awk '{print $2}')" "$@" </dev/null; }
elif [ "$(id -un)" = "$OWNER" ]; then
  mkdir -p "$PREFIX" || { echo "ERROR: $PREFIX is not writable for $OWNER and we are not root"; exit 4; }
  AS_OWNER() { "$@" </dev/null; }
else echo "ERROR: run as root or as the owner"; exit 4; fi

# GIT_TERMINAL_PROMPT=0 + GIT_CONFIG_NOSYSTEM=1: never ask for a password and never use the macOS keychain helper
# (set in the system gitconfig) -- a root script on a client Mac has no screen to show a prompt on.
# --- 2. Clone brew as the owner -----------------------------------------------------------------------------
echo "Cloning $REMOTE into $PREFIX as $OWNER ..."
AS_OWNER env GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 "$GIT" clone --quiet "$REMOTE" "$PREFIX" || { echo "ERROR: git clone failed"; exit 6; }
[ -x "$PREFIX/bin/brew" ] || { echo "ERROR: clone finished but $PREFIX/bin/brew is missing"; exit 6; }
# Quiet, no auto-update, no analytics; --version proves brew runs as the owner.
AS_OWNER env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 "$PREFIX/bin/brew" --version
echo "Homebrew installed at $PREFIX, owned by $OWNER."
exit 0
