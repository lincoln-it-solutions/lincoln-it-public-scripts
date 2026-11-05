#!/bin/sh
# Test-BrewOwnerPick.sh -- READ-ONLY. Runs Invoke-BrewManagedSoftware.sh --show-owner three ways and prints what it would choose
# as the owner of a NEW Homebrew: (1) default rules, (2) BREW_OWNER set to the current user, (3) BREW_OWNER set to a name that does
# not exist (must refuse). Nothing is installed or changed. Uses 'env -i' so no stray environment leaks in.
S="$(dirname "$0")/Invoke-BrewManagedSoftware.sh"
ME=$(id -un)
echo "---- 1. default rules";                       env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh "$S" --show-owner 2>&1
echo "---- 2. BREW_OWNER=$ME (expect: chosen)";      env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin BREW_OWNER="$ME" /bin/sh "$S" --show-owner 2>&1
echo "---- 3. BREW_OWNER=nosuchuser (expect: refused)"; env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin BREW_OWNER=nosuchuser /bin/sh "$S" --show-owner 2>&1
