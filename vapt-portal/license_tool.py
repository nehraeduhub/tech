#!/usr/bin/env python3
"""Tech Guardians license management CLI (owner tool).

Workflow
--------
1. ONE TIME — create your signing keypair (keep the private key SECRET):
     python license_tool.py genkeys
   Paste the printed PUBLIC key into config.LICENSE_PUBLIC_KEY and set
   LICENSE_ENFORCE = True. Store the private key file somewhere safe and never
   ship it.

2. A user who wants to run the tool sends you their machine fingerprint:
     python license_tool.py fingerprint

3. You issue them a license bound to that fingerprint:
     python license_tool.py issue --licensee "Acme Corp" \
         --fingerprint <their-fingerprint> --days 365 \
         --private rjhex_private.key --out license.key
   Send them license.key; they place it next to app.py.

Run `python license_tool.py <command> -h` for options.
"""
from __future__ import annotations

import argparse
import json
import sys

from security import licensing


def cmd_genkeys(args):
    priv, pub = licensing.generate_keypair()
    with open(args.private_out, "w", encoding="utf-8") as fh:
        fh.write(priv)
    print("Keypair generated.\n")
    print(f"  Private key written to: {args.private_out}")
    print("  >>> KEEP THIS FILE SECRET. Never ship it. Anyone with it can issue "
          "licenses. <<<\n")
    print("  PUBLIC key (paste into config.LICENSE_PUBLIC_KEY):\n")
    print(f"    LICENSE_PUBLIC_KEY = \"{pub}\"\n")
    print("  Then set  LICENSE_ENFORCE = True  in config.py.")


def cmd_fingerprint(args):
    print(licensing.machine_fingerprint())


def cmd_issue(args):
    with open(args.private, "r", encoding="utf-8") as fh:
        priv_hex = fh.read().strip()
    from datetime import date, timedelta
    expires = args.expires or (date.today() + timedelta(days=args.days)).isoformat()
    lic = licensing.issue_license(
        private_key_hex=priv_hex, licensee=args.licensee,
        fingerprint=args.fingerprint, expires=expires, edition=args.edition,
    )
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(lic, fh, indent=2)
    print(f"License issued for '{args.licensee}' -> {args.out}")
    print(f"  Machine : {args.fingerprint}")
    print(f"  Expires : {expires}")
    print("  Send this file to the user; they place it beside app.py as "
          "'license.key'.")


def cmd_verify(args):
    import config
    try:
        lic = licensing.load_license(args.file)
        licensing.verify_license(lic, config.LICENSE_PUBLIC_KEY)
        print("License is VALID for this machine.")
        print(json.dumps({k: v for k, v in lic.items() if k != "signature"},
                         indent=2))
    except licensing.LicenseError as exc:
        print(f"License INVALID: {exc}")
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="Tech Guardians license management (owner tool)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkeys", help="generate a signing keypair")
    g.add_argument("--private-out", default="rjhex_private.key")
    g.set_defaults(func=cmd_genkeys)

    f = sub.add_parser("fingerprint", help="print this machine's fingerprint")
    f.set_defaults(func=cmd_fingerprint)

    i = sub.add_parser("issue", help="issue a license (needs the private key)")
    i.add_argument("--licensee", required=True)
    i.add_argument("--fingerprint", required=True)
    i.add_argument("--days", type=int, default=365)
    i.add_argument("--expires", help="YYYY-MM-DD (overrides --days)")
    i.add_argument("--edition", default="standard")
    i.add_argument("--private", default="rjhex_private.key")
    i.add_argument("--out", default="license.key")
    i.set_defaults(func=cmd_issue)

    v = sub.add_parser("verify", help="verify a license on this machine")
    v.add_argument("--file", default="license.key")
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
