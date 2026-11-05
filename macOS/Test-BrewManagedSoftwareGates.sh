#!/bin/sh
# Test-BrewManagedSoftwareGates.sh -- REPORT-ONLY test of Invoke-BrewManagedSoftware.sh.
# Feeds the script the environment variables TRMM would pass, one case at a time, and prints the exit
# code and output. Never passes --apply, so nothing is installed, changed or removed.
S="$(dirname "$0")/Invoke-BrewManagedSoftware.sh"
case_() {   # case_ "<label>" "<expected exit>" VAR=val ...
  label="$1"; want="$2"; shift 2
  echo "---- $label  (expect exit $want)"
  out=$(env -i PATH="$PATH" HOME="$HOME" "$@" sh "$S" 2>&1); rc=$?
  printf '%s\n' "$out" | sed 's/^/   /'
  [ "$rc" = "$want" ] && echo "   => exit $rc  PASS" || echo "   => exit $rc  FAIL (wanted $want)"
}
T='$True'; F='$False'      # single-quoted so the shell does not expand them: TRMM sends the literal text
case_ "PAYG client"                    0  SERVICE_TIER="PAYG" BREW_ENABLED="$T" BREW_CLIENT_PACKAGES="google-chrome"
case_ "Not Under Support"              0  SERVICE_TIER="Not Under Support" BREW_ENABLED="$T" BREW_CLIENT_PACKAGES="google-chrome"
case_ "switch unticked"                0  SERVICE_TIER="Support" BREW_ENABLED="$F" BREW_CLIENT_PACKAGES="google-chrome"
case_ "switch missing/empty"           0  SERVICE_TIER="Support" BREW_ENABLED="" BREW_CLIENT_PACKAGES="google-chrome"
case_ "ticked, all lists empty"        0  SERVICE_TIER="Support" BREW_ENABLED="$T"
case_ "unresolved placeholder"        12  SERVICE_TIER="Support" BREW_ENABLED="$T" BREW_SITE_PACKAGES="{{site.Brew Install Packages}}"
case_ "blank tier + ticked + client list (fail-open)" 0 SERVICE_TIER="" BREW_ENABLED="$T" BREW_CLIENT_PACKAGES="google-chrome, visual-studio-code"
case_ "site beats client"              0  SERVICE_TIER="Support" BREW_ENABLED="True" BREW_SITE_PACKAGES="microsoft-edge" BREW_CLIENT_PACKAGES="google-chrome"
case_ "device beats site and client"   0  SERVICE_TIER="Support" BREW_ENABLED="1" BREW_AGENT_PACKAGES='["google-chrome"]' BREW_SITE_PACKAGES="microsoft-edge"
case_ "unknown cask is skipped"        0  SERVICE_TIER="Support" BREW_ENABLED="$T" BREW_CLIENT_PACKAGES="somethingelse"
