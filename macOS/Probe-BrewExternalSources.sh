#!/bin/sh
# Probe-BrewExternalSources.sh -- READ-ONLY. Finds out which env vars the installed Homebrew honours for where it
# downloads its portable Ruby / bottles / casks / API data from, by reading Homebrew's own source and man page.
# Why: the test log showed brew fetching portable-ruby from ghcr.io, so mirroring the brew git repo alone may not
# remove the dependency on outside hosts. This prints evidence; it changes nothing.
B=/opt/homebrew
echo "== brew version"; "$B/bin/brew" --version 2>&1 | head -2
echo "== files that mention portable-ruby download"
grep -rIl -E "portable-ruby|HOMEBREW_PORTABLE_RUBY" "$B/Library/Homebrew" --include=*.sh --include=*.rb 2>/dev/null | head -10
echo "== vendor-install.sh lines on domains/urls"
for f in "$B/Library/Homebrew/cmd/vendor-install.sh" "$B/Library/Homebrew/vendor-install.sh"; do
  [ -f "$f" ] && { echo "-- $f"; grep -n -E "DOMAIN|ghcr|_URL|REMOTE|curl" "$f" | head -40; }
done
echo "== man page: domain/remote variables"
M="$B/share/man/man1/brew.1"; [ -f "$M" ] && grep -n -E -A2 "HOMEBREW_(BOTTLE_DOMAIN|ARTIFACT_DOMAIN|API_DOMAIN|BREW_GIT_REMOTE|CORE_GIT_REMOTE|NO_INSTALL_FROM_API)" "$M" | head -60
