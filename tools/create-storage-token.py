#!/usr/bin/env python3
"""Create an HMAC-signed bearer credential for a Vulnobs storage tenant."""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import time


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True, help="stable ID for this Grafana installation")
    parser.add_argument("--lifetime-days", type=int, default=365)
    args = parser.parse_args()

    signing_key = os.environ.get("VULNOBS_TOKEN_SIGNING_KEY", "").encode()
    if len(signing_key) < 32:
        parser.error("VULNOBS_TOKEN_SIGNING_KEY must contain at least 32 bytes")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", args.tenant_id):
        parser.error("tenant ID must be 1-128 characters: letters, digits, dot, underscore, colon, or hyphen")
    if not 1 <= args.lifetime_days <= 3650:
        parser.error("lifetime-days must be from 1 to 3650")

    payload = json.dumps(
        {"tenant": args.tenant_id, "exp": int(time.time()) + args.lifetime_days * 86400},
        separators=(",", ":"),
    ).encode()
    unsigned = "v1." + b64url(payload)
    signature = hmac.new(signing_key, unsigned.encode(), hashlib.sha256).digest()
    print(unsigned + "." + b64url(signature))


if __name__ == "__main__":
    main()
