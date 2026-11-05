#!/bin/sh
# Probe-PkgChoices.sh -- READ-ONLY. Downloads the Teams pkg from Microsoft (to a temp folder, deleted afterwards) and asks the
# macOS installer to LIST the install choices it contains (installer -showChoiceChangesXML). Nothing is installed.
# Why: the draft Teams manifest switches off the choice 'com.microsoft.autoupdate' (Microsoft AutoUpdate), copied from Homebrew's
# cask. This confirms that exact choice id exists in Microsoft's pkg before we rely on it. Result also saved to _snapshots.
T=$(mktemp -d /tmp/pkgchoices.XXXXXX); trap 'rm -rf "$T"' EXIT
curl -fL --retry 3 -o "$T/t.pkg" "https://go.microsoft.com/fwlink/?linkid=2249065" || { echo "download failed"; exit 1; }
# -showChoiceChangesXML prints the choice tree as a plist; -target / is only used to evaluate it, nothing is written.
installer -pkg "$T/t.pkg" -target / -showChoiceChangesXML > "$T/choices.plist" 2>"$T/err.txt"
echo "installer exit: $?"; cat "$T/err.txt" | head -5
mkdir -p "$HOME/GIT/_snapshots"; cp "$T/choices.plist" "$HOME/GIT/_snapshots/teams_choices.plist"
grep -E 'choiceIdentifier|choiceAttribute|attributeSetting' -A1 "$T/choices.plist" | grep -E '<string>|<integer>' | head -40
