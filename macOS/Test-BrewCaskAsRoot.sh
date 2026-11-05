#!/bin/sh
# Test-BrewCaskAsRoot.sh -- TEST ONLY. Proves a Homebrew cask can be installed/removed from a
# ROOT script (as TRMM runs it) by switching to the account that owns Homebrew.
#
# Usage: Test-BrewCaskAsRoot.sh check | install google-chrome | uninstall google-chrome
#
# Why this design:
#  - TRMM runs scripts as root, but Homebrew refuses to run as root, so we run brew as the
#    owner of /opt/homebrew. Root can switch user with 'sudo -u' without a password.
#  - stdin is /dev/null so that if brew ever asks for a password it fails at once instead of
#    hanging the TRMM run (the failure we are testing for with non-sudo casks).
#  - Only google-chrome is allowed here on purpose: this is a test, not the production script.
MODE="$1"; CASK="$2"
BREW=/opt/homebrew/bin/brew

[ "$(id -u)" -eq 0 ] || { echo "FAIL: must run as root (as TRMM does)"; exit 2; }
[ -x "$BREW" ]      || { echo "FAIL: no Homebrew at $BREW"; exit 3; }

# The Homebrew owner = whoever owns the brew binary. Never root.
OWNER=$(stat -f%Su "$BREW")
[ "$OWNER" != "root" ] || { echo "FAIL: Homebrew owned by root"; exit 4; }
id -Gn "$OWNER" | tr ' ' '\n' | grep -qx admin || { echo "FAIL: owner $OWNER is not an admin"; exit 5; }
OWNER_HOME=$(dscl . -read "/Users/$OWNER" NFSHomeDirectory | awk '{print $2}')
echo "owner: $OWNER  home: $OWNER_HOME"

case "$CASK" in google-chrome|"") ;; *) echo "FAIL: test allows google-chrome only"; exit 6;; esac

# Run brew as the owner, quietly and non-interactively (no auto-update, no analytics, no prompts).
runbrew() {
  sudo -H -u "$OWNER" env HOME="$OWNER_HOME" HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 \
    HOMEBREW_NO_INSTALL_CLEANUP=1 NONINTERACTIVE=1 "$BREW" "$@" </dev/null 2>&1
}

case "$MODE" in
  check)
    # Changes nothing: version, whether --adopt exists, and what a dry run would do.
    runbrew --version | head -1
    echo "--adopt supported by 'brew install'?"; runbrew install --help | grep -i -- "--adopt" || echo "  not listed"
    echo "dry run:"; runbrew install --cask --dry-run google-chrome
    ;;
  install)
    runbrew install --cask "$CASK"; echo "brew exit: $?"
    echo "--- verify ---"
    ls -ld "/Applications/Google Chrome.app" 2>&1
    runbrew list --cask --versions
    ;;
  uninstall)
    runbrew uninstall --cask "$CASK"; echo "brew exit: $?"
    echo "--- verify ---"
    ls -ld "/Applications/Google Chrome.app" 2>&1
    ;;
  *) echo "usage: check | install <cask> | uninstall <cask>"; exit 1;;
esac
