#!/bin/sh
# Survey-VendorUrlHeaders.sh -- READ-ONLY. Sends HEAD requests (headers only, no file download) to candidate vendor URLs and prints
# status, size, last-modified and any redirect. Why: confirms whether a URL really exists on the vendor's server and how big/new it is,
# without trusting third-party sites. Adobe: the cask version (26.001.21662) vs the newer version a news post mentioned (26.002.21901).
# Teams: the URL Homebrew's cask uses. Nothing is installed or saved.
for u in \
  "https://ardownload2.adobe.com/pub/adobe/reader/mac/AcrobatDC/2600121662/AcroRdrDC_2600121662_MUI.dmg" \
  "https://ardownload2.adobe.com/pub/adobe/reader/mac/AcrobatDC/2600221901/AcroRdrDC_2600221901_MUI.dmg" \
  "https://statics.teams.cdn.office.net/production-osx/26276.505.5234.9924/MicrosoftTeams.pkg"
do
  echo "== $u"
  # -I = HEAD, -L = follow redirects, -s silent; print only the useful header lines
  curl -sIL --max-time 30 "$u" | grep -iE '^(HTTP/|content-length|last-modified|content-type|location)'
done
