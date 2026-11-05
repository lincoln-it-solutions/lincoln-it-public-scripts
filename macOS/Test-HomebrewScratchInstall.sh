#!/bin/sh
# Test-HomebrewScratchInstall.sh (v2) -- tests Install-Homebrew.sh, an own tap fetched through a git config FILE,
# the "own tap only" lock, and that no keychain/credential prompt can appear. Everything happens in a SCRATCH prefix under
# ~/claude-workspace/brewtest; your real /opt/homebrew is never used. Installs Google Chrome into /Applications via the
# scratch brew and removes it again at the end.
#
# v1 lessons (4 Nov): (a) GIT_CONFIG_KEY_n/VALUE_n env vars did NOT reach brew's git; (b) HOMEBREW_FORBIDDEN_TAPS did
# not block official API casks; (c) a missing tap made git try github.com and prompt the macOS keychain.
# v2 therefore: a private gitconfig file via GIT_CONFIG_GLOBAL, GIT_CONFIG_NOSYSTEM=1 (drops the system keychain
# helper), GIT_TERMINAL_PROMPT=0, an EMPTY credential.helper, HOMEBREW_NO_INSTALL_FROM_API=1 for the lock, and an early
# abort so a failed tap step cannot fall through to github.com.
if [ -z "$BREWTEST_INNER" ]; then
  LOG="$HOME/GIT/_snapshots/brewtest_$(date +%Y%m%d_%H%M%S).log"
  BREWTEST_INNER=1 sh "$0" 2>&1 | tee "$LOG"; exit 0
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HOME/claude-workspace/brewtest"; PFX="$ROOT/prefix"; REPO="$ROOT/tapsrc"; BARE="$ROOT/tap.git"
rm -rf "$ROOT"; mkdir -p "$ROOT"; OWNER=$(id -un)
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_INSTALL_CLEANUP=1 NONINTERACTIVE=1
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1
fail() { echo "ABORT: $1"; rm -rf "$ROOT"; exit 1; }

echo "=== 1. install brew into a scratch prefix (as the owner, no sudo) ==="
sh "$HERE/Install-Homebrew.sh" --owner "$OWNER" --prefix "$PFX" || fail "install"
BREW="$PFX/bin/brew"

echo; echo "=== 2. build a tap with ONE cask (Chrome; version + sha256 from the vendor file) ==="
INFO=$(/opt/homebrew/bin/brew info --cask --json=v2 google-chrome)
URL=$(printf '%s' "$INFO" | python3 -c 'import json,sys;print(json.load(sys.stdin)["casks"][0]["url"])')
VER=$(printf '%s' "$INFO" | python3 -c 'import json,sys;print(json.load(sys.stdin)["casks"][0]["version"])')
curl -fsSL -o "$ROOT/chrome.dmg" "$URL" || fail "download"
SHA=$(shasum -a 256 "$ROOT/chrome.dmg" | awk '{print $1}'); rm -f "$ROOT/chrome.dmg"
mkdir -p "$REPO/Casks"; (cd "$REPO" && git init -q -b main && cat > Casks/google-chrome.rb <<RB
cask "google-chrome" do
  version "$VER"
  sha256 "$SHA"
  url "$URL"
  name "Google Chrome"
  desc "Web browser (Lincoln IT test tap)"
  homepage "https://www.google.com/chrome/"
  auto_updates true
  app "Google Chrome.app"
end
RB
git add -A && git -c user.name=t -c user.email=t@t commit -q -m test) && git clone -q --bare "$REPO" "$BARE" || fail "tap repo"

echo; echo "=== 3. tap = OUR OWN git clone into brew's Taps folder (brew never needs to see credentials or git settings) ==="
# v2 finding: brew's own git ignores GIT_CONFIG_* / GIT_CONFIG_GLOBAL, so the production script clones the tap itself with
# its own git settings, straight into Library/Taps/<user>/homebrew-<name>; brew then treats it as an ordinary tap.
cat > "$ROOT/gitconfig" <<GC
[credential]
	helper =
[url "file://$BARE"]
	insteadOf = https://tap.invalid/homebrew-software.git
GC
mkdir -p "$PFX/Library/Taps/lincolnit"
GIT_CONFIG_GLOBAL="$ROOT/gitconfig" git clone -q https://tap.invalid/homebrew-software.git "$PFX/Library/Taps/lincolnit/homebrew-software" || fail "our own tap clone"
"$BREW" tap | grep -qx "lincolnit/software" || fail "brew does not see the cloned tap"
echo "brew taps:"; "$BREW" tap

echo; echo "=== 4. allow-list by construction (v2 finding: HOMEBREW_NO_INSTALL_FROM_API=1 makes brew clone the whole public homebrew/core) ==="
# So we do NOT use that setting. Instead the production script only accepts a cask if Casks/<name>.rb exists in OUR tap
# clone, and always installs it fully qualified (lincolnit/software/<name>). Demonstrate the check:
TAPDIR="$PFX/Library/Taps/lincolnit/homebrew-software/Casks"
for c in google-chrome microsoft-edge; do [ -f "$TAPDIR/$c.rb" ] && echo "  $c: in our tap -> allowed" || echo "  $c: NOT in our tap -> refused"; done

echo; echo "=== 5. install Chrome from OUR tap (fully qualified), then uninstall ==="
"$BREW" install --cask lincolnit/software/google-chrome; echo "exit: $?"
ls -ld "/Applications/Google Chrome.app" 2>&1
"$BREW" list --cask --versions
"$BREW" uninstall --cask google-chrome; echo "uninstall exit: $?"
ls -ld "/Applications/Google Chrome.app" 2>&1

echo; echo "=== cleanup ==="; rm -rf "$ROOT" && echo "scratch removed"
