#!/bin/sh
# Probe-SudoForOwner.sh -- READ-ONLY. Changes nothing.
#
# Why: Homebrew runs as an owning (admin) user and calls sudo for casks that need elevated
# rights (.pkg installers). From a root RMM script there is no one to type a password, so we
# need to know whether the owner can use sudo WITHOUT a password on this Mac.
#
# 'sudo -n' = never prompt; it just fails if a password would be needed. 'sudo -n -v' only
# validates credentials -- it runs no command and changes nothing.
echo "running as: $(id -un)"
if sudo -n -v 2>/dev/null; then
  echo "RESULT: sudo works WITHOUT a password for this user"
else
  echo "RESULT: sudo needs a password for this user (non-interactive sudo fails)"
fi
