#!/bin/sh
# Stop-HomebrewScratchTest.sh -- stops a running Test-HomebrewScratchInstall.sh and deletes its scratch folder.
# Only touches processes whose command line mentions the scratch folder / the test script, and only that folder.
pkill -f "claude-workspace/brewtest" 2>/dev/null
pkill -f "Test-HomebrewScratchInstall" 2>/dev/null
sleep 2
rm -rf "$HOME/claude-workspace/brewtest" && echo "scratch removed"
pgrep -fl "brewtest|Test-HomebrewScratchInstall" || echo "no test processes left"
