#!/bin/sh
# Survey-PkgCasks.sh -- READ-ONLY. For the three pkg-based apps we want (Edge, Adobe Acrobat Reader, Teams) prints what Homebrew's
# CURRENT cask definition says: version, download URL, sha256, the artifacts (pkg/app/uninstall list), whether the app updates
# itself (auto_updates) and the livecheck rule. Uses the existing /opt/homebrew read-only (brew info); installs nothing.
# Why: the pkg installer we are writing must follow each vendor's real packaging, not guesses.
B=/opt/homebrew/bin/brew
for c in microsoft-edge adobe-acrobat-reader microsoft-teams; do
  echo "================ $c"
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 "$B" info --cask --json=v2 "$c" 2>&1 | python3 -c '
import json, sys
raw = sys.stdin.read()
try: d = json.loads(raw)["casks"][0]
except Exception: print("could not parse brew output:", raw[:300]); sys.exit()
for k in ("token", "version", "url", "sha256", "auto_updates", "depends_on", "deprecated", "disabled"):
    print(f"{k}: {d.get(k)}")
print("url_specs:", d.get("url_specs"))
print("artifacts:")
for a in d.get("artifacts", []):
    s = json.dumps(a); print("  ", s[:600])
' 
done
