#!/bin/sh
# Probe-BrewVendorBearer.sh -- READ-ONLY. Sends the SAME Authorization header brew sends (brew.sh line 652 default,
# "Bearer QQ==") to our Ruby mirror URL with NO password, and prints the HTTP status only.
# Why: brew printed our mirror URL then fell back to ghcr.io; this tests whether the edge proxy rejects brew's header.
U=https://software.lincolnitsolutions.co.uk/brew-vendor/portable-ruby-4.0.9.arm64_big_sur.bottle.tar.gz
echo "brew's Bearer header, no login:"; curl -sS -o /dev/null -w "HTTP %{http_code}\n" -H "Authorization: Bearer QQ==" "$U"
echo "no header at all:";               curl -sS -o /dev/null -w "HTTP %{http_code}\n" "$U"
