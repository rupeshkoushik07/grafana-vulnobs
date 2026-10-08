#!/usr/bin/env python3
"""Import an existing Vulnobs assets.json file into the authenticated storage API."""

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assets_file", type=Path, help="path to the previous assets.json file")
    parser.add_argument("storage_url", help="base URL of the Vulnobs storage API")
    args = parser.parse_args()

    token = os.environ.get("VULNOBS_STORAGE_TOKEN", "")
    if len(token) < 32:
        parser.error("set VULNOBS_STORAGE_TOKEN to the configured 32-character or longer token")

    parsed = urlparse(args.storage_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
        parser.error("storage_url must be an absolute HTTP(S) URL without user information")

    with args.assets_file.open(encoding="utf-8") as source:
        store = json.load(source)
    assets = store.get("assets", [])
    if not isinstance(assets, list):
        parser.error("assets.json must contain an assets array")

    opener = urllib.request.build_opener(NoRedirect)
    endpoint = args.storage_url.rstrip("/") + "/v1/assets"
    for asset in assets:
        body = json.dumps(asset).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="PUT",
        )
        try:
            with opener.open(request, timeout=30) as response:
                if response.status not in (200, 201, 204):
                    raise RuntimeError(f"storage API returned HTTP {response.status}")
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"storage API returned HTTP {error.code}") from error
        print(f"imported {asset.get('asset', '<unnamed>')}")

    print(f"Imported {len(assets)} assets")


if __name__ == "__main__":
    main()
