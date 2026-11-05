#!/bin/sh
# Invoke-MacPkgSoftware.sh -- installs vendor .pkg apps (Edge, Adobe Reader, Teams ...) that OUR private tap describes.
# REPORT ONLY unless called with --apply. Runs as root (TRMM does). Does NOT use Homebrew: `installer` needs root and
# Homebrew refuses root, so pkg apps are installed here directly. Casks (Chrome, VS Code ...) stay with Invoke-BrewManagedSoftware.sh.
#
# GATES (same order and rules as Invoke-BrewManagedSoftware.sh; the first that applies ends the run with exit 0, no action):
#   1. SERVICE_TIER = PAYG / Not Under Support -> exit 0 (blank = run).  2. BREW_ENABLED not ticked -> exit 0.
#   3. No packages in device/site/client list -> exit 0.   The list is the same custom-field list the brew script uses.
#
# WHICH NAMES: only names that have Pkgs/<name>.conf in our tap. Anything else is ignored here (casks belong to the brew script).
#
# TRUST MODEL (why each check exists)
#   - The manifest (url/file, sha256, Developer ID team id) comes from OUR private tap, pushed by a different account from the
#     one that uploads the installer files. Someone who swaps a stored file cannot also change the hash that pins it.
#   - Before running `installer` we check: sha256 of the download equals the manifest; the pkg is signed by a Developer ID
#     Installer certificate whose Team ID equals the pinned one; Gatekeeper accepts it (notarised). Any failure = refuse.
#   - INSTALL-ONLY: if the app is already installed we never touch it, even when the tap has a newer version (the vendors'
#     own updaters keep these apps current; pinning against them just fights). It reports the difference only.
#
# Manifest format (Pkgs/<name>.conf, plain key=value, parsed strictly - never sourced as shell):
#   name=  version=  kind=pkg|dmg-pkg  file=<file name on our host>  sha256=<64 hex of that file>  team_id=<10 chars>
#   pkg_id=<receipt id used to detect the installed version>  app=<path of the .app, to spot installs done outside>
#   inner_pkg=<pkg name inside the dmg; kind=dmg-pkg only>  deselect=<comma list of installer choice ids to switch off, optional>
#
# Environment (TRMM passes the same ones as the brew script): SERVICE_TIER BREW_ENABLED BREW_AGENT_PACKAGES BREW_SITE_PACKAGES
#   BREW_CLIENT_PACKAGES, BREW_MIRROR_PASSWORD (only needed with --apply).
#   TESTING ONLY: PKG_TAP_DIR (use this folder as the tap, no git), PKG_SOURCE_DIR (take files from this folder, no download).
#
# Exit codes: 0 ok/gated  1 an app failed  12 setup problem (unresolved placeholder, not root for --apply)  14 tap fetch failed
# Usage: Invoke-MacPkgSoftware.sh [--apply]
APPLY=0
for a in "$@"; do case "$a" in --apply) APPLY=1;; *) echo "unknown argument: $a"; exit 12;; esac; done

HOST="${BREW_MIRROR_HOST:-https://software.lincolnitsolutions.co.uk}"
MIRROR_USER=choco-agent
GIT=/Library/Developer/CommandLineTools/usr/bin/git          # CLT git only: /usr/bin/git is a stub that pops a dialog if CLT is missing
TAP_DIR="${PKG_TAP_DIR:-/Library/Application Support/LincolnIT/tap}"
PKG_URL_BASE="$HOST/mac-pkgs"                                 # where the upload step will publish files (not built yet)

# --- 0. Unresolved TRMM placeholders: fail loudly rather than act on literal '{{...}}' text ---------------------
for v in SERVICE_TIER BREW_ENABLED BREW_AGENT_PACKAGES BREW_SITE_PACKAGES BREW_CLIENT_PACKAGES; do
  eval "val=\${$v}"
  case "$val" in *'{{'*) echo "ERROR: $v still contains '{{...}}' - TRMM did not resolve the custom field."; exit 12;; esac
done
if [ "$APPLY" -eq 1 ]; then
  [ "$(id -u)" -eq 0 ] || { echo "ERROR: --apply needs root (installer runs as root)."; exit 12; }
  case "$BREW_MIRROR_PASSWORD" in ''|*'{{'*) [ -n "$PKG_SOURCE_DIR" ] || { echo "ERROR: BREW_MIRROR_PASSWORD is empty or unresolved."; exit 12; };; esac
fi

# --- 1-3. Gates (identical rules to the brew script) ----------------------------------------------------------
tier=$(printf '%s' "$SERVICE_TIER" | sed 's/^ *//;s/ *$//')
case "$tier" in "PAYG"|"Not Under Support") echo "GATED: service tier is '$tier' - no software management. Nothing done."; exit 0;; esac
en=$(printf '%s' "$BREW_ENABLED" | tr 'A-Z' 'a-z' | sed 's/^\$//;s/^ *//;s/ *$//')
case "$en" in true|1) ;; *) echo "GATED: client switch 'Install Homebrew' is not ticked. Nothing done."; exit 0;; esac
has_value() { [ -n "$(printf '%s' "$1" | tr -d '[:space:]')" ]; }
if   has_value "$BREW_AGENT_PACKAGES";  then raw="$BREW_AGENT_PACKAGES";  origin=DEVICE
elif has_value "$BREW_SITE_PACKAGES";   then raw="$BREW_SITE_PACKAGES";   origin=SITE
elif has_value "$BREW_CLIENT_PACKAGES"; then raw="$BREW_CLIENT_PACKAGES"; origin=CLIENT
else echo "No packages assigned at device, site or client level - nothing to do."; exit 0; fi
ids=$(printf '%s' "$raw" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9._+@\n-' '\n' | sed '/^$/d' | sort -u)
[ -n "$ids" ] || { echo "ERROR: the $origin value '$raw' contains no usable names."; exit 1; }
echo "Packages assigned ($origin): $(printf '%s' "$ids" | tr '\n' ' ')"

# --- 4. Secrets and scratch space, removed on exit -------------------------------------------------------------
WORK=; cleanup() { [ -n "$WORK" ] && { hdiutil detach "$WORK/mnt" -force >/dev/null 2>&1; rm -rf "$WORK"; }; }
trap cleanup EXIT
if [ "$APPLY" -eq 1 ]; then
  WORK=$(mktemp -d /private/tmp/macpkg.XXXXXX) || { echo "ERROR: cannot create temp dir"; exit 12; }
  chmod 700 "$WORK"
  # curl reads its login from a config file (mode 600) so the password never appears on a command line (visible in `ps`).
  umask 077
  printf 'user = "%s:%s"\n' "$MIRROR_USER" "$BREW_MIRROR_PASSWORD" > "$WORK/curl.cfg"
  printf '#!/bin/sh\necho username=%s\necho "password=$(cat "%s/pw")"\n' "$MIRROR_USER" "$WORK" > "$WORK/helper"
  printf '%s' "$BREW_MIRROR_PASSWORD" > "$WORK/pw"; chmod 500 "$WORK/helper"
fi
mirror_git() { env GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 "$GIT" -c credential.helper= -c "credential.helper=$WORK/helper" "$@"; }

# --- 5. Our tap: clone or update it (--apply only; no PKG_TAP_DIR override) -------------------------------------
if [ "$APPLY" -eq 1 ] && [ -z "$PKG_TAP_DIR" ]; then
  mkdir -p "$(dirname "$TAP_DIR")"
  if [ -d "$TAP_DIR/.git" ]; then mirror_git -C "$TAP_DIR" pull --quiet --ff-only "$HOST/git/homebrew-software.git" main || { echo "ERROR: tap update failed"; exit 14; }
  else mirror_git clone --quiet "$HOST/git/homebrew-software.git" "$TAP_DIR" || { echo "ERROR: tap clone failed"; exit 14; }; fi
fi

# Read one key from a manifest. Strict: only the first 'key=' line, value up to end of line, no shell evaluation.
mget() { sed -n "s/^$2=//p" "$1" | head -1 | tr -d '\r'; }

failed=0
for id in $ids; do
  man="$TAP_DIR/Pkgs/$id.conf"
  if [ ! -d "$TAP_DIR" ]; then echo "WOULD CLONE our tap to read manifests (report-only), then handle $id if it is a pkg app"; continue; fi
  [ -f "$man" ] || { echo "-       $id: no pkg manifest in our tap (casks are handled by the brew script)"; continue; }

  # Validate the manifest before trusting any value in it.
  version=$(mget "$man" version); kind=$(mget "$man" kind); file=$(mget "$man" file); sha=$(mget "$man" sha256)
  team=$(mget "$man" team_id); pkgid=$(mget "$man" pkg_id); app=$(mget "$man" app); inner=$(mget "$man" inner_pkg); desel=$(mget "$man" deselect)
  bad=
  case "$kind" in pkg|dmg-pkg) ;; *) bad="kind";; esac
  printf '%s' "$sha"  | grep -Eq '^[0-9a-f]{64}$'        || bad="$bad sha256"
  printf '%s' "$team" | grep -Eq '^[A-Z0-9]{10}$'        || bad="$bad team_id"
  printf '%s' "$file" | grep -Eq '^[A-Za-z0-9._-]+$'     || bad="$bad file"
  printf '%s' "$pkgid" | grep -Eq '^[A-Za-z0-9._-]+$'    || bad="$bad pkg_id"
  [ -n "$version" ] || bad="$bad version"
  [ "$kind" != dmg-pkg ] || printf '%s' "$inner" | grep -Eq '^[A-Za-z0-9._-]+\.pkg$' || bad="$bad inner_pkg"
  if [ -n "$bad" ]; then echo "FAILED  $id: manifest invalid/missing:$bad - refusing"; failed=1; continue; fi

  # Already installed? Detect through the pkg receipt (what the installer itself records), not by file names.
  have=$(pkgutil --pkg-info "$pkgid" 2>/dev/null | sed -n 's/^version: //p')
  if [ -n "$have" ]; then
    if [ "$have" = "$version" ]; then echo "OK      $id: installed, version $have (matches tap)"
    else echo "OK      $id: installed, version $have; tap has $version - not changed (install-only; the app updates itself)"; fi
    continue
  fi
  if [ -n "$app" ] && [ -e "$app" ]; then echo "SKIP    $id: '$app' is already installed without our receipt (not installed over)"; continue; fi
  if [ "$APPLY" -ne 1 ]; then echo "WOULD INSTALL  $id $version ($kind, signer team $team)"; continue; fi

  # ---- install ----
  echo "INSTALLING $id $version"
  dl="$WORK/$file"
  if [ -n "$PKG_SOURCE_DIR" ]; then cp "$PKG_SOURCE_DIR/$file" "$dl" || { echo "FAILED  $id: test source file missing"; failed=1; continue; }
  else curl -fsSL --retry 3 --max-time 3600 -K "$WORK/curl.cfg" -o "$dl" "$PKG_URL_BASE/$file" || { echo "FAILED  $id: download from our host failed"; failed=1; continue; }; fi
  got=$(shasum -a 256 "$dl" | awk '{print $1}')
  [ "$got" = "$sha" ] || { echo "FAILED  $id: sha256 mismatch (got $got, tap says $sha) - NOT installing"; failed=1; rm -f "$dl"; continue; }
  pkg="$dl"
  if [ "$kind" = dmg-pkg ]; then
    mkdir -p "$WORK/mnt"
    hdiutil attach -nobrowse -readonly -mountpoint "$WORK/mnt" "$dl" >/dev/null || { echo "FAILED  $id: cannot mount dmg"; failed=1; continue; }
    [ -f "$WORK/mnt/$inner" ] || { echo "FAILED  $id: $inner not found in dmg"; failed=1; hdiutil detach "$WORK/mnt" >/dev/null 2>&1; continue; }
    cp "$WORK/mnt/$inner" "$WORK/inner.pkg"; hdiutil detach "$WORK/mnt" >/dev/null 2>&1; pkg="$WORK/inner.pkg"
  fi
  sig=$(pkgutil --check-signature "$pkg" 2>&1); sigrc=$?
  signer_team=$(printf '%s' "$sig" | sed -n 's/.*Developer ID Installer: .* (\([A-Z0-9]\{10\}\)).*/\1/p' | head -1)
  [ $sigrc -eq 0 ] && [ "$signer_team" = "$team" ] || { echo "FAILED  $id: signature check failed (rc $sigrc, signer team '${signer_team:-none}', pinned '$team') - NOT installing"; failed=1; continue; }
  spctl --assess --type install "$pkg" >/dev/null 2>&1 || { echo "FAILED  $id: Gatekeeper/notarisation check failed - NOT installing"; failed=1; continue; }

  # Optional installer choices to switch off (e.g. Teams bundles Microsoft AutoUpdate). Built as the plist installer expects.
  choicearg=
  if [ -n "$desel" ]; then
    plist="$WORK/choices.plist"
    { echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><array>'
      for c in $(printf '%s' "$desel" | tr ',' ' '); do
        printf '<dict><key>attributeSetting</key><integer>0</integer><key>choiceAttribute</key><string>selected</string><key>choiceIdentifier</key><string>%s</string></dict>' "$c"
      done
      echo '</array></plist>'; } > "$plist"
    choicearg="-applyChoiceChangesXML $plist"
  fi
  # shellcheck disable=SC2086   # choicearg is intentionally split into two words
  installer -pkg "$pkg" -target / $choicearg || { echo "FAILED  $id: installer exited non-zero"; failed=1; continue; }
  now=$(pkgutil --pkg-info "$pkgid" 2>/dev/null | sed -n 's/^version: //p')
  if [ "$now" = "$version" ]; then echo "DONE    $id: receipt shows $now"
  else echo "FAILED  $id: installer finished but receipt '$pkgid' shows '${now:-none}', expected $version"; failed=1; fi
  rm -f "$dl" "$WORK/inner.pkg"
done
[ "$failed" -eq 0 ] || exit 1
exit 0
