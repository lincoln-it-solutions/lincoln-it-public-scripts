#!/bin/sh
# Survey-VendorPkgEndpoints.sh -- READ-ONLY. Fetches Microsoft's own Edge release feed and prints the Stable MacOS entries
# (version, artifact type, URL, hash). Why: Homebrew's cask says Edge ships as a dmg, but an earlier look at this feed showed only
# a pkg. We need the vendor's own answer before choosing how to install Edge. Downloads nothing but the small JSON feed.
# python3 does the parsing so we print exactly what the feed contains, nothing inferred.
curl -fsS --max-time 30 "https://edgeupdates.microsoft.com/api/products?view=enterprise" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for prod in data:
    if prod.get("Product") != "Stable":
        continue
    for rel in prod.get("Releases", []):
        if rel.get("Platform") != "MacOS":
            continue
        print("Version:", rel.get("ProductVersion"), "| Arch:", rel.get("Architecture"), "| Published:", rel.get("PublishedTime"))
        for a in rel.get("Artifacts", []):
            print("   ", a.get("ArtifactName"), "|", a.get("Location"), "|", a.get("HashAlgorithm"), a.get("Hash"))
'
