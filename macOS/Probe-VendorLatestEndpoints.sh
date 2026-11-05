#!/bin/sh
# Probe-VendorLatestEndpoints.sh -- READ-ONLY. Tests two UNVERIFIED guesses at where the vendors publish "what is current":
#  1) Adobe's updater manifest for Reader on Mac (armmf.adobe.com ... current_version.txt) -- small text file.
#  2) Microsoft's Teams macOS "latest" redirect (go.microsoft.com/fwlink linkid=2249065) -- HEAD only, shows where it redirects.
# Why: the tap updater must find the newest version from the vendor itself, not from Homebrew. Anything that 404s is a wrong guess.
echo "== Adobe manifest (GET, small)"
curl -sS --max-time 30 -w '\nHTTP %{http_code}\n' "https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/reader/current_version.txt" | head -5
echo
echo "== Teams fwlink (HEAD, follow redirects, headers only)"
curl -sIL --max-time 30 "https://go.microsoft.com/fwlink/?linkid=2249065" | grep -iE '^(HTTP/|location|content-length|last-modified)'
