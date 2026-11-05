#!/bin/sh
# Probe-HomebrewReadiness.sh -- READ-ONLY. Changes nothing on the Mac.
#
# Why: before building Homebrew management for Macs we need facts, not assumptions:
#   - which account is the script running as (root? the logged-in user?)
#   - who is the console (logged-in) user, and are they in the 'admin' group?
#   - which accounts are admins on this Mac?
#   - is Homebrew already installed, where, owned by whom?
#   - CPU architecture + macOS version (Homebrew supports Apple Silicon on Sequoia+).
#   - is the Tactical RMM agent installed here (so the same probe can be run through TRMM)?
# Output is plain text so it can be pasted back or captured by TRMM.

echo "== Identity of the account running this script =="
echo "user: $(id -un)  uid: $(id -u)"
echo "groups: $(id -Gn)"

# The console user is whoever is logged in at the screen. Under TRMM/root this differs
# from the running user, which is exactly what we need to find out.
console_user=$(stat -f%Su /dev/console 2>/dev/null)
echo
echo "== Console (logged-in) user =="
echo "console user: ${console_user:-unknown}"
# 'admin' group membership is what makes a macOS account an administrator.
if [ -n "$console_user" ] && id -Gn "$console_user" 2>/dev/null | tr ' ' '\n' | grep -qx admin; then
  echo "console user is an ADMIN"
else
  echo "console user is NOT an admin (or not determinable)"
fi

echo
echo "== Admin group members on this Mac =="
dscl . -read /Groups/admin GroupMembership 2>/dev/null

echo
echo "== System =="
sw_vers 2>/dev/null
echo "arch: $(uname -m)"

echo
echo "== Homebrew =="
# /opt/homebrew = Apple Silicon default prefix, /usr/local = Intel default prefix.
found=0
for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
  if [ -x "$b" ]; then
    found=1
    echo "found: $b  owner: $(stat -f%Su "$b")"
    "$b" --version 2>/dev/null | head -1
  fi
done
[ "$found" -eq 0 ] && echo "Homebrew not found at the default prefixes"

echo
echo "== Xcode Command Line Tools =="
xcode-select -p 2>&1

echo
echo "== Tactical RMM agent on this Mac (process/paths are a best guess; absence is not proof) =="
pgrep -fl -i tactical 2>/dev/null || echo "no process matching 'tactical'"
ls -d /opt/tacticalagent* /usr/local/mesh_services 2>/dev/null || true
