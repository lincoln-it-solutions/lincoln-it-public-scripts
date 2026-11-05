#!/bin/sh
# Survey-CaskArtifacts.sh -- READ-ONLY. Installs/changes nothing.
#
# Why: casks installed by an owner account without sudo must be app bundles (dmg/zip -> .app).
# Casks using a .pkg installer need elevated rights. For each Mac equivalent of our managed
# Windows software list, this shows what Homebrew's own cask data says the cask installs
# (artifact types), the download URL's file extension, and whether the app is already installed.
#
# HOMEBREW_NO_AUTO_UPDATE stops brew changing anything on its own; 'brew info' only reads.
BREW=/opt/homebrew/bin/brew
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1

# Candidate casks = the Mac counterparts of our Chocolatey list (7zip/Office/Remote Help/DrayTek
# have no obvious same-name cask, so the ones that map are listed; others are checked separately).
for c in google-chrome microsoft-edge adobe-acrobat-reader visual-studio-code zoom microsoft-teams microsoft-office microsoft-remote-help 7zip; do
  echo "=== $c ==="
  # python3 pulls just the facts we need out of brew's JSON (artifact keys, URL, auto_updates).
  "$BREW" info --cask --json=v2 "$c" 2>/dev/null | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)["casks"][0]
except Exception:
    print("  not found as a cask"); sys.exit()
kinds=[list(a.keys())[0] for a in d.get("artifacts",[])]
print("  version:", d.get("version"), "| auto_updates:", d.get("auto_updates"))
print("  artifacts:", sorted(set(kinds)))
print("  url:", d.get("url"))
'
  # Already installed via brew?  (read-only list)
  "$BREW" list --cask 2>/dev/null | grep -qx "$c" && echo "  installed via brew: yes" || echo "  installed via brew: no"
done
echo
echo "== Apps present in /Applications (name only) =="
ls /Applications | grep -i -E "chrome|edge|acrobat|visual studio|zoom|teams|word|remote help" || echo "none of the candidates found"
