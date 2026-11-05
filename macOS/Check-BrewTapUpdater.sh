#!/bin/sh
# Check-BrewTapUpdater.sh -- TRMM script CHECK for the Homebrew private-tap updater. Runs on the ONE Mac that acts as the
# updater (Lincoln IT's own Air), as root. It fails (exit 1, an alert) when either half of the pipeline has gone stale:
#   1. the updater Mac's status file (written by publish_tap.sh): last run failed, or no success in the last 48 hours;
#   2. the choc-rep mirror heartbeat (https://<host>/brew-vendor/last-refresh.txt, written by brew-mirror.service only when
#      the nightly refresh succeeded): missing or older than 36 hours.
# Environment (set on the TRMM check):
#   TAP_STATUS_FILE   full path of the updater's status file, e.g. /Users/<user>/Library/Logs/LincolnIT/tap-publish.status
#   BREW_MIRROR_HOST  optional, default https://software.lincolnitsolutions.co.uk
# No service-tier gate on purpose: this watches OUR OWN infrastructure and is assigned to one agent only.
# Exit codes: 0 healthy   1 stale/failed (alert)   2 setup problem (missing env var / unreadable file)
TAP_MAX_HOURS=48        # updater is daily; allow one missed day (Mac asleep/away)
MIRROR_MAX_HOURS=36     # server refresh is daily at ~03:30
HOST="${BREW_MIRROR_HOST:-https://software.lincolnitsolutions.co.uk}"
fail=0
now=$(date -u +%s)
# ISO UTC timestamp (2026-11-05T06:30:00Z) -> epoch seconds. macOS date syntax; prints nothing if unparseable.
to_epoch() { date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$1" +%s 2>/dev/null; }

case "$TAP_STATUS_FILE" in ''|*'{{'*) echo "SETUP: TAP_STATUS_FILE is empty or unresolved."; exit 2;; esac

# --- 1. updater status file -----------------------------------------------------------------------------
if [ ! -r "$TAP_STATUS_FILE" ]; then
  echo "FAIL  updater status file not found: $TAP_STATUS_FILE (the updater has never run, or the path is wrong)"; fail=1
else
  res=$(sed -n 's/^result=//p' "$TAP_STATUS_FILE"); last_run=$(sed -n 's/^last_run=//p' "$TAP_STATUS_FILE"); ok=$(sed -n 's/^last_success=//p' "$TAP_STATUS_FILE")
  echo "updater: last_run=$last_run result=$res last_success=${ok:-never}"
  [ "$res" = "ok" ] || { echo "FAIL  the last updater run did not succeed ($res)"; fail=1; }
  e=$(to_epoch "$ok")
  if [ -z "$e" ]; then echo "FAIL  the updater has no recorded success"; fail=1
  else age=$(( (now - e) / 3600 )); [ "$age" -le "$TAP_MAX_HOURS" ] || { echo "FAIL  last updater success was ${age}h ago (limit ${TAP_MAX_HOURS}h)"; fail=1; }; fi
fi

# --- 2. mirror heartbeat on choc-rep ----------------------------------------------------------------------
hb=$(curl -fsS -m 20 "$HOST/brew-vendor/last-refresh.txt" 2>/dev/null | tr -d '[:space:]')
e=$(to_epoch "$hb")
if [ -z "$e" ]; then echo "FAIL  mirror heartbeat missing or unreadable at $HOST/brew-vendor/last-refresh.txt (got '${hb}')"; fail=1
else age=$(( (now - e) / 3600 )); echo "mirror: last successful refresh $hb (${age}h ago)"
  [ "$age" -le "$MIRROR_MAX_HOURS" ] || { echo "FAIL  mirror refresh is ${age}h old (limit ${MIRROR_MAX_HOURS}h) - check brew-mirror.service on choc-rep"; fail=1; }; fi

[ "$fail" -eq 0 ] && echo "OK  tap updater and mirror refresh are both current." 
exit "$fail"
