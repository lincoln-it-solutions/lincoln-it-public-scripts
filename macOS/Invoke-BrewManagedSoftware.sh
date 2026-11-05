#!/bin/sh
# Invoke-BrewManagedSoftware.sh -- manage the Homebrew casks assigned to this Mac (TRMM, runs as root).
# Mac counterpart of the Windows Chocolatey scripts (301-304). FIRST VERSION: app-bundle casks only
# (google-chrome, microsoft-edge, visual-studio-code). REPORT ONLY unless called with --apply.
#
# GATES -- checked in this order; the first one that applies ends the run with exit 0 and NO action:
#   1. SERVICE_TIER   PAYG or Not Under Support = exit 0. Blank/unresolved = run (fail-open, same rule as the
#                     Windows scripts).
#   2. BREW_ENABLED   the client switch "Install Homebrew" must be ticked. TRMM passes a ticked box as the text
#                     "$True" (see Invoke-RebootNag.ps1). Anything else = exit 0.
#   3. No packages    which list is used: DEVICE value if set, else SITE, else CLIENT. Empty everywhere = exit 0.
#                     So Homebrew is never installed or touched on a Mac that has no list.
#
# TRMM SETUP (environment variables on the script/task):
#   SERVICE_TIER={{client.Service Tier}}
#   BREW_ENABLED={{client.Install Homebrew}}
#   BREW_AGENT_PACKAGES={{agent.Brew Install Packages}}
#   BREW_SITE_PACKAGES={{site.Brew Install Packages}}
#   BREW_CLIENT_PACKAGES={{client.Brew Install Packages}}
#   BREW_MIRROR_PASSWORD={{global.choco_proxy_password}}   (TRMM Global Keystore; the choco-agent login for our mirror.
#                     Only needed with --apply; used for git clone/pull of OUR tap, never put on a command line.)
#   Optional: BREW_OWNER (admin account that should own a NEW Homebrew; see WHO OWNS below).
#   Optional overrides for TESTING only: BREW_PREFIX (default /opt/homebrew), BREW_MIRROR_HOST.
#   Text still containing '{{' means a field name did not resolve (case sensitive) -> exit 12, nothing done.
#   NOT YET VERIFIED: how a ticked multi-select arrives; the parser accepts commas, spaces, new lines, [ ] " '.
#
# WHAT IT DOES (with --apply)
#   - finds the Homebrew OWNER (owner of /opt/homebrew/bin/brew; must be an admin, never root). TRMM runs us as
#     root and Homebrew refuses root, so every brew command is run as the owner with 'sudo -u' (tested 4 Nov).
#   - for each assigned cask: already managed by brew = OK; app already in /Applications but not managed by brew =
#     SKIP (reported; only adopted if you also pass --adopt, because adopting reinstalled apps on 12 PCs under
#     Chocolatey); otherwise 'brew install --cask'.
#   - with --upgrade: 'brew upgrade --cask' for the assigned casks that brew says are outdated.
#   - stdin is /dev/null so a password prompt FAILS instead of hanging the run. App-bundle casks need no sudo.
#
# PRIVATE MIRROR (like the Chocolatey feed): nothing comes from Homebrew's public cask list.
#   - Homebrew itself is cloned from OUR mirror  (HOST/git/brew.git); its portable Ruby comes from HOST/brew-vendor/.
#   - Casks come only from OUR tap lincolnit/software (HOST/git/homebrew-software.git), cloned by this script straight
#     into <prefix>/Library/Taps/lincolnit/homebrew-software (brew's own git ignores our git settings, so we do it).
#   - A cask is accepted ONLY if Casks/<name>.rb exists in that tap, and it is always installed fully qualified
#     (lincolnit/software/<name>), so an official cask of the same name can never be picked up.
#   - Homebrew missing + --apply: installed without sudo (root creates /opt/homebrew and hands it to the owner; the owner
#     clones brew into it). Report-only mode never installs anything. Tested only in a scratch prefix (4 Nov).
#   - git is run with GIT_TERMINAL_PROMPT=0 and GIT_CONFIG_NOSYSTEM=1 and an empty credential helper first, so there is
#     never a prompt or a macOS keychain dialog on a client Mac.
#   - The Homebrew OWNER must already exist: an admin account that is not root. If Homebrew is missing, the owner is the
#     logged-in console user if that user is an admin (otherwise exit 11: no usable owner; standard-user case not built).
#
# EXIT CODES: 0 ok / gated / nothing to do   1 a cask failed or list invalid   10 Homebrew missing (report-only run)
#             11 no usable owner account      12 setup problem (unresolved placeholder, not root for --apply)
#             13 Homebrew install failed      14 tap clone/update failed
#
# WHO OWNS A NEW HOMEBREW (only when Homebrew is missing; an existing install keeps its owner). First match wins:
#   1. env BREW_OWNER, if set (must be an existing admin account);
#   2. the logged-in console user, if that user is an admin;
#   3. the ONLY human admin account on the Mac (admin group member, not root, UID >= 501, name not starting with '_');
#   4. otherwise nothing is guessed: exit 11, listing the admin accounts found, so a standard-user Mac with several
#      admins needs BREW_OWNER set on its TRMM script/task.
#   --show-owner prints which owner would be chosen and exits (read-only, no gates, nothing installed).
#
# Usage: Invoke-BrewManagedSoftware.sh [--apply] [--adopt] [--upgrade] [--show-owner]
APPLY=0; ADOPT=0; UPGRADE=0; SHOWOWNER=0
for a in "$@"; do
  case "$a" in --apply) APPLY=1;; --adopt) ADOPT=1;; --upgrade) UPGRADE=1;; --show-owner) SHOWOWNER=1;; *) echo "unknown argument: $a"; exit 12;; esac
done

# --- Owner selection helpers (used only when Homebrew has to be installed) --------------------------------------
is_admin() { id -Gn "$1" 2>/dev/null | tr ' ' '\n' | grep -qx admin; }
# Human admin accounts: members of the admin group, minus root and service accounts (names starting '_'), UID >= 501.
human_admins() {
  for u in $(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership://'); do
    case "$u" in root|_*) continue;; esac
    uid=$(dscl . -read "/Users/$u" UniqueID 2>/dev/null | awk '{print $2}')
    [ -n "$uid" ] && [ "$uid" -ge 501 ] && echo "$u"
  done
}
# Prints the chosen owner on stdout and the reason on stderr; prints nothing when it cannot choose.
pick_owner() {
  con=$(stat -f%Su /dev/console 2>/dev/null)
  if [ -n "$BREW_OWNER" ]; then
    if id "$BREW_OWNER" >/dev/null 2>&1 && [ "$BREW_OWNER" != root ] && is_admin "$BREW_OWNER"; then echo "owner: BREW_OWNER setting" >&2; echo "$BREW_OWNER"; return 0
    else echo "BREW_OWNER='$BREW_OWNER' is not an existing non-root admin account" >&2; return 1; fi
  fi
  if [ -n "$con" ] && [ "$con" != root ] && [ "$con" != loginwindow ] && is_admin "$con"; then echo "owner: the logged-in user is an admin" >&2; echo "$con"; return 0; fi
  admins=$(human_admins); n=$(printf '%s\n' "$admins" | sed '/^$/d' | wc -l | tr -d ' ')
  if [ "$n" -eq 1 ]; then echo "owner: the only human admin account (console user '${con:-none}' is not an admin)" >&2; echo "$admins"; return 0; fi
  echo "no owner can be chosen: console user '${con:-none}', human admin accounts found: $n ($(printf '%s' "$admins" | tr '\n' ' '))" >&2; return 1
}
if [ "$SHOWOWNER" -eq 1 ]; then
  echo "console user: $(stat -f%Su /dev/console 2>/dev/null); human admins: $(human_admins | tr '\n' ' ')"
  o=$(pick_owner) && echo "WOULD CHOOSE: $o" || echo "WOULD CHOOSE: nobody (exit 11)"
  exit 0
fi
# Where everything lives. BREW_PREFIX / BREW_MIRROR_HOST can be overridden for TESTING (scratch prefix) only.
PREFIX="${BREW_PREFIX:-/opt/homebrew}"
BREW="$PREFIX/bin/brew"
HOST="${BREW_MIRROR_HOST:-https://software.lincolnitsolutions.co.uk}"
MIRROR_USER=choco-agent
TAP_NAME=lincolnit/software
TAP_DIR="$PREFIX/Library/Taps/lincolnit/homebrew-software"
GIT=/Library/Developer/CommandLineTools/usr/bin/git   # CLT git only: /usr/bin/git is a stub that pops a dialog if CLT is missing

# --- 0. Unresolved TRMM placeholders: fail loudly rather than act on literal '{{...}}' text -------------------
for v in SERVICE_TIER BREW_ENABLED BREW_AGENT_PACKAGES BREW_SITE_PACKAGES BREW_CLIENT_PACKAGES; do
  eval "val=\${$v}"
  case "$val" in *'{{'*) echo "ERROR: $v still contains '{{...}}' - TRMM did not resolve the custom field (names are case sensitive)."; exit 12;; esac
done

# The mirror password is only needed to change things. Report-only runs never touch the mirror.
if [ "$APPLY" -eq 1 ]; then
  case "$BREW_MIRROR_PASSWORD" in
    ''|*'{{'*) echo "ERROR: BREW_MIRROR_PASSWORD is empty or unresolved - check the Global Keystore entry choco_proxy_password."; exit 12;; esac
fi

# --- 1. Service tier gate -----------------------------------------------------------------------------------
tier=$(printf '%s' "$SERVICE_TIER" | sed 's/^ *//;s/ *$//')
case "$tier" in
  "PAYG"|"Not Under Support") echo "GATED: service tier is '$tier' - no software management. Nothing done."; exit 0;;
esac

# --- 2. Client switch "Install Homebrew" ------------------------------------------------------------------
# Accept the text TRMM sends for a ticked checkbox: $True / True / true / 1 (case-insensitive, optional leading $).
en=$(printf '%s' "$BREW_ENABLED" | tr 'A-Z' 'a-z' | sed 's/^\$//;s/^ *//;s/ *$//')
case "$en" in true|1) ;; *) echo "GATED: client switch 'Install Homebrew' is not ticked. Nothing done."; exit 0;; esac

# --- 3. Which list: device, else site, else client ------------------------------------------------------------
has_value() { [ -n "$(printf '%s' "$1" | tr -d '[:space:]')" ]; }
if   has_value "$BREW_AGENT_PACKAGES";  then raw="$BREW_AGENT_PACKAGES";  origin=DEVICE; echo "Using the DEVICE list (site and client lists ignored)."
elif has_value "$BREW_SITE_PACKAGES";   then raw="$BREW_SITE_PACKAGES";   origin=SITE;   echo "Device list empty - using the SITE list (client list ignored)."
elif has_value "$BREW_CLIENT_PACKAGES"; then raw="$BREW_CLIENT_PACKAGES"; origin=CLIENT; echo "Device and site lists empty - using the CLIENT list."
else echo "No packages assigned at device, site or client level - nothing to do."; exit 0; fi

# Parse: split on anything that is not part of a cask token (lower case letters, digits, . _ + @ -).
ids=$(printf '%s' "$raw" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9._+@\n-' '\n' | sed '/^$/d' | sort -u)
[ -n "$ids" ] || { echo "ERROR: the $origin value '$raw' contains no usable cask names."; exit 1; }
echo "Packages assigned ($origin): $(printf '%s' "$ids" | tr '\n' ' ')"

# --- 4. Homebrew + its owner -------------------------------------------------------------------------------
if [ -x "$BREW" ]; then
  OWNER=$(stat -f%Su "$BREW")
else
  # Homebrew missing. Report-only: say so and stop (exit 10). With --apply it is installed below, owned by the
  # logged-in console user if that user is an admin (Homebrew must belong to an admin; root is never allowed).
  if [ "$APPLY" -ne 1 ]; then echo "WOULD INSTALL HOMEBREW into $PREFIX (report-only: nothing installed). Re-run with --apply."; exit 10; fi
  if [ "$(id -u)" -eq 0 ]; then OWNER=$(pick_owner) || { echo "ERROR: Homebrew is missing and no admin account could be chosen to own it. Set BREW_OWNER. Not installing."; exit 11; }
  else OWNER=$(id -un); is_admin "$OWNER" || { echo "ERROR: Homebrew is missing and $OWNER is not an admin. Not installing."; exit 11; }; fi
fi
[ "$OWNER" != "root" ] || { echo "ERROR: Homebrew is owned by root."; exit 11; }
is_admin "$OWNER" || { echo "ERROR: Homebrew owner '$OWNER' is not an admin."; exit 11; }
OWNER_HOME=$(dscl . -read "/Users/$OWNER" NFSHomeDirectory | awk '{print $2}')
echo "Homebrew owner: $OWNER"

# Run something as the owner (root -> sudo -u, which needs no password for root; the owner themselves -> directly).
as_owner() {
  if [ "$(id -u)" -eq 0 ]; then sudo -H -u "$OWNER" env HOME="$OWNER_HOME" "$@" </dev/null
  elif [ "$(id -un)" = "$OWNER" ]; then env "$@" </dev/null
  else echo "ERROR: must run as root or as the Homebrew owner"; return 12; fi
}
if [ "$APPLY" -eq 1 ] && [ "$(id -u)" -ne 0 ] && [ "$(id -un)" != "$OWNER" ]; then echo "ERROR: --apply needs root (as TRMM) or the owner."; exit 12; fi

# --- 4b. Credentials for OUR mirror (only with --apply) -------------------------------------------------------
# The password goes into a file only the owner can read; git's credential helper (a tiny script) prints it when git asks.
# This keeps it out of every command line (visible in 'ps') and out of any persistent git/keychain config. All removed on exit.
SECRETDIR=
cleanup() { [ -n "$SECRETDIR" ] && rm -rf "$SECRETDIR"; }
trap cleanup EXIT
GITENV="GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1"      # never prompt, never use the system gitconfig (osxkeychain helper)
if [ "$APPLY" -eq 1 ]; then
  SECRETDIR=$(mktemp -d /tmp/brewmirror.XXXXXX) || { echo "ERROR: cannot create temp dir"; exit 12; }
  printf '%s' "$BREW_MIRROR_PASSWORD" > "$SECRETDIR/pw"
  printf '#!/bin/sh\necho username=%s\necho "password=$(cat "%s/pw")"\n' "$MIRROR_USER" "$SECRETDIR" > "$SECRETDIR/helper"
  chmod 600 "$SECRETDIR/pw"; chmod 500 "$SECRETDIR/helper"          # only the owner may read the password / run the helper
  chown "$OWNER" "$SECRETDIR/pw" "$SECRETDIR/helper" 2>/dev/null    # (no-op when we already ARE the owner)
  chmod 711 "$SECRETDIR"                                            # owner can reach the files; others cannot list them
fi
# git as the owner against our mirror: first an EMPTY credential.helper (clears the keychain helper), then ours.
mirror_git() { as_owner $GITENV "$GIT" -c credential.helper= -c "credential.helper=$SECRETDIR/helper" "$@"; }

# --- 4c. Install Homebrew from OUR mirror if it is missing (--apply only) ------------------------------------------
if [ ! -x "$BREW" ]; then
  [ "$(uname -m)" = "arm64" ] || [ "$PREFIX" != "/opt/homebrew" ] || { echo "ERROR: /opt/homebrew is the Apple Silicon prefix; this Mac is $(uname -m)"; exit 13; }
  if [ -d "$PREFIX" ] && [ -n "$(ls -A "$PREFIX" 2>/dev/null)" ]; then echo "ERROR: $PREFIX exists, is not empty and has no bin/brew - not touching it."; exit 13; fi
  # Command Line Tools supply git. Same method as Homebrew's own installer (softwareupdate with a marker file). UNTESTED.
  if [ ! -x "$GIT" ]; then
    [ "$(id -u)" -eq 0 ] || { echo "ERROR: Command Line Tools missing and not root."; exit 13; }
    echo "Command Line Tools missing - installing via softwareupdate..."
    touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
    LABEL=$(softwareupdate -l 2>/dev/null | grep -B1 -E "Command Line Tools" | awk -F'*' '/^ *\*/ {print $2}' | sed -e 's/^ *Label: //' -e 's/^ *//' | sort -V | tail -n1)
    [ -n "$LABEL" ] && softwareupdate -i "$LABEL" --verbose
    rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
    [ -x "$GIT" ] || { echo "ERROR: Command Line Tools install failed."; exit 13; }
  fi
  # Root creates the prefix and hands it to the owner (no password needed for root); the owner then clones brew into it.
  if [ "$(id -u)" -eq 0 ]; then mkdir -p "$PREFIX" && chown "$OWNER":admin "$PREFIX" && chmod 755 "$PREFIX" || { echo "ERROR: cannot create $PREFIX"; exit 13; }
  else mkdir -p "$PREFIX" || { echo "ERROR: cannot create $PREFIX"; exit 13; }; fi
  echo "Installing Homebrew from our mirror into $PREFIX as $OWNER ..."
  mirror_git clone --quiet "$HOST/git/brew.git" "$PREFIX" || { echo "ERROR: clone of brew from our mirror failed"; exit 13; }
  [ -x "$BREW" ] || { echo "ERROR: clone finished but $BREW is missing"; exit 13; }
fi

# Run brew as the owner. HOMEBREW_BOTTLE_DOMAIN makes brew fetch its portable Ruby from OUR host first (it falls back to
# ghcr.io only if ours fails). Auto-update/analytics/cleanup off, never interactive, stdin from /dev/null.
runbrew() {
  as_owner HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_INSTALL_CLEANUP=1 NONINTERACTIVE=1 \
    HOMEBREW_BOTTLE_DOMAIN="$HOST/brew-vendor" "$BREW" "$@" 2>&1
}

# --- 4d. Our tap: clone or update it straight into brew's Taps folder (--apply only) ----------------------------
if [ "$APPLY" -eq 1 ]; then
  if [ -d "$TAP_DIR/.git" ]; then
    echo "Updating our tap ..."
    mirror_git -C "$TAP_DIR" pull --quiet --ff-only "$HOST/git/homebrew-software.git" main || { echo "ERROR: tap update failed"; exit 14; }
  else
    echo "Cloning our tap into $TAP_DIR ..."
    as_owner mkdir -p "$(dirname "$TAP_DIR")" || { echo "ERROR: cannot create the Taps folder"; exit 14; }
    mirror_git clone --quiet "$HOST/git/homebrew-software.git" "$TAP_DIR" || { echo "ERROR: tap clone failed"; exit 14; }
  fi
fi
# A cask is allowed only if our tap has Casks/<name>.rb (checked by construction; no network needed).
in_tap() { [ -f "$TAP_DIR/Casks/$1.rb" ]; }

# --- 5. Per cask ------------------------------------------------------------------------------------------
# Display names of the .app each first-version cask installs (to spot copies installed outside brew).
app_for() { case "$1" in
  google-chrome) echo "Google Chrome.app";; microsoft-edge) echo "Microsoft Edge.app";;
  visual-studio-code) echo "Visual Studio Code.app";; *) echo "";; esac; }
managed=$(runbrew list --cask 2>/dev/null)
failed=0
for id in $ids; do
  if printf '%s\n' "$managed" | grep -qx "$id"; then echo "OK      $id: already managed by Homebrew"; continue; fi
  app=$(app_for "$id")
  if [ ! -d "$TAP_DIR/.git" ]; then echo "WOULD CLONE our tap, then install $id if it is in the tap (report-only)"; continue; fi
  if ! in_tap "$id"; then echo "SKIP    $id: not in our private tap ($TAP_NAME) - never taken from the public list"; continue; fi
  if [ -z "$app" ]; then echo "SKIP    $id: not in the first-version cask list (google-chrome, microsoft-edge, visual-studio-code)"; continue; fi
  if [ -e "/Applications/$app" ]; then
    if [ "$ADOPT" -eq 1 ] && [ "$APPLY" -eq 1 ]; then
      echo "ADOPTING $id (existing /Applications/$app)"; runbrew install --cask --adopt "$TAP_NAME/$id"; rc=$?
      [ $rc -eq 0 ] || { echo "FAILED  $id: adopt exit $rc"; failed=1; }
    else echo "SKIP    $id: '$app' is already installed outside Homebrew (not installed over; adoption needs --adopt --apply)"; fi
    continue
  fi
  if [ "$APPLY" -ne 1 ]; then echo "WOULD INSTALL  $id"; continue; fi
  echo "INSTALLING $id"; runbrew install --cask "$TAP_NAME/$id"; rc=$?
  [ $rc -eq 0 ] || { echo "FAILED  $id: exit $rc"; failed=1; }
done

# --- 6. Optional upgrade of the assigned casks that are outdated --------------------------------------------
if [ "$UPGRADE" -eq 1 ]; then
  outdated=$(runbrew outdated --cask --quiet 2>/dev/null)
  for id in $ids; do
    if printf '%s\n' "$outdated" | grep -qx "$id"; then
      if [ "$APPLY" -ne 1 ]; then echo "WOULD UPGRADE  $id"; continue; fi
      echo "UPGRADING $id"; runbrew upgrade --cask "$TAP_NAME/$id"; rc=$?
      [ $rc -eq 0 ] || { echo "FAILED  $id: upgrade exit $rc"; failed=1; }
    fi
  done
fi

[ "$failed" -eq 0 ] || exit 1
exit 0
