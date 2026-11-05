#!/bin/sh
# Test-MacPkgSoftware.sh -- SAFE tests of Invoke-MacPkgSoftware.sh: report-only mode, a throwaway tap folder, no network, no root,
# nothing installed. Proves the gates, manifest validation and report lines. It does NOT prove the --apply path (download,
# hash/signature checks, installer) - that needs root and a throwaway Mac (the test VM).
S="$(dirname "$0")/Invoke-MacPkgSoftware.sh"
DRAFT="$(dirname "$0")/../../it-flow-trmm-stack/Homebrew/pkg-manifests-draft/Pkgs"
T=$(mktemp -d /tmp/pkgtest.XXXXXX); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/Pkgs"; cp "$DRAFT"/*.conf "$T/Pkgs/"
pass=0; fail=0
# check NAME EXPECTED_EXIT "REGEX that output must match" ENV...   (env assignments follow)
check() { name=$1; want=$2; rx=$3; shift 3
  out=$(env PKG_TAP_DIR="$T" "$@" sh "$S" 2>&1); rc=$?
  if [ "$rc" -eq "$want" ] && printf '%s' "$out" | grep -Eq "$rx"; then echo "PASS  $name"; pass=$((pass+1))
  else echo "FAIL  $name (exit $rc, wanted $want, wanted /$rx/)"; printf '%s\n' "$out" | sed 's/^/        /'; fail=$((fail+1)); fi; }
OK="SERVICE_TIER=Support BREW_ENABLED=1"
check "PAYG is gated"            0 'GATED: service tier'  SERVICE_TIER=PAYG BREW_ENABLED=1 BREW_CLIENT_PACKAGES=microsoft-edge
check "Not Under Support gated"  0 'GATED: service tier'  "SERVICE_TIER=Not Under Support" BREW_ENABLED=1 BREW_CLIENT_PACKAGES=microsoft-edge
check "switch off is gated"      0 'GATED: client switch' SERVICE_TIER=Support BREW_ENABLED=0 BREW_CLIENT_PACKAGES=microsoft-edge
check "empty list = nothing"     0 'nothing to do'        SERVICE_TIER=Support BREW_ENABLED=1
check "unresolved placeholder"   12 'still contains'      SERVICE_TIER='{{x}}' BREW_ENABLED=1 BREW_CLIENT_PACKAGES=microsoft-edge
check "cask name ignored here"   0 'no pkg manifest'      SERVICE_TIER=Support BREW_ENABLED=1 BREW_CLIENT_PACKAGES=google-chrome
check "report-only never installs" 0 'WOULD INSTALL|installed|already installed' SERVICE_TIER=Support BREW_ENABLED=1 BREW_CLIENT_PACKAGES=microsoft-edge,adobe-acrobat-reader,microsoft-teams
check "device list beats client" 0 'Packages assigned \(DEVICE\): microsoft-teams' SERVICE_TIER=Support BREW_ENABLED=1 BREW_AGENT_PACKAGES=microsoft-teams BREW_CLIENT_PACKAGES=microsoft-edge
# Bad manifests must be refused, not guessed at.
sed 's/^sha256=.*/sha256=nothex/' "$T/Pkgs/microsoft-edge.conf" > "$T/x" && mv "$T/x" "$T/Pkgs/microsoft-edge.conf"
check "bad sha256 refused"       1 'manifest invalid.*sha256' SERVICE_TIER=Support BREW_ENABLED=1 BREW_CLIENT_PACKAGES=microsoft-edge
cp "$DRAFT/microsoft-edge.conf" "$T/Pkgs/"; sed 's/^team_id=.*/team_id=short/' "$T/Pkgs/microsoft-edge.conf" > "$T/x" && mv "$T/x" "$T/Pkgs/microsoft-edge.conf"
check "bad team_id refused"      1 'manifest invalid.*team_id' SERVICE_TIER=Support BREW_ENABLED=1 BREW_CLIENT_PACKAGES=microsoft-edge
cp "$DRAFT/microsoft-edge.conf" "$T/Pkgs/"; sed 's#^file=.*#file=../../etc/passwd#' "$T/Pkgs/microsoft-edge.conf" > "$T/x" && mv "$T/x" "$T/Pkgs/microsoft-edge.conf"
check "path in file refused"     1 'manifest invalid.*file' SERVICE_TIER=Support BREW_ENABLED=1 BREW_CLIENT_PACKAGES=microsoft-edge
echo "$pass passed, $fail failed"; [ "$fail" -eq 0 ]
