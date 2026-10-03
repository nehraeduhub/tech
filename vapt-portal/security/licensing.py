"""Machine-locked licensing for the RJHex VAPT Portal.

Design
------
* The OWNER holds an Ed25519 PRIVATE key (never shipped). It is used to issue
  licenses with ``license_tool.py``.
* The app ships only the Ed25519 PUBLIC key (safe to distribute) and uses it to
  VERIFY a license file. Nobody can forge a valid license without the private
  key.
* A license is bound to a specific machine FINGERPRINT and an EXPIRY date, so a
  copied folder will not run on another machine or after the license lapses.

Enforcement is controlled by ``config.LICENSE_ENFORCE``. When False (default),
the portal runs unrestricted -- useful before you have set up keys. Set it to
True once you have embedded your public key and issued a license.

NOTE: this is source-shipped software. Licensing deters casual copying/sharing
but a determined person with the source can bypass any client-side check. For
stronger protection, distribute a compiled binary (see PACKAGING in SECURITY.md).
"""
from __future__ import annotations

import base64
import hashlib
import json
import platform
import socket
import uuid
from datetime import date, datetime
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    _HAVE_CRYPTO = False


class LicenseError(Exception):
    """Raised when a license is missing, invalid, expired or machine-mismatched."""


# --------------------------------------------------------------------------- #
# Machine fingerprint
# --------------------------------------------------------------------------- #
def machine_fingerprint() -> str:
    """A stable-ish fingerprint for the current machine.

    Combines OS, architecture, hostname and the primary NIC's hardware address.
    Hashed so it is opaque and safe to share with the licensor.
    """
    node = uuid.getnode()  # 48-bit MAC-derived identifier
    raw = "|".join([
        platform.system(),
        platform.machine(),
        socket.gethostname(),
        str(node),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# --------------------------------------------------------------------------- #
# Canonical payload used for signing/verifying
# --------------------------------------------------------------------------- #
def _canonical_payload(lic: dict) -> bytes:
    payload = {
        "licensee": lic.get("licensee", ""),
        "fingerprint": lic.get("fingerprint", ""),
        "issued": lic.get("issued", ""),
        "expires": lic.get("expires", ""),
        "edition": lic.get("edition", "standard"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# --------------------------------------------------------------------------- #
# Owner-side helpers (require the PRIVATE key)
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex). Keep the private key secret."""
    _require_crypto()
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv_bytes.hex(), pub_bytes.hex()


def issue_license(private_key_hex: str, licensee: str, fingerprint: str,
                  expires: str, edition: str = "standard") -> dict:
    """Create a signed license dict (owner-only; needs the private key)."""
    _require_crypto()
    datetime.strptime(expires, "%Y-%m-%d")  # validate format
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    lic = {
        "licensee": licensee,
        "fingerprint": fingerprint,
        "issued": date.today().isoformat(),
        "expires": expires,
        "edition": edition,
    }
    sig = priv.sign(_canonical_payload(lic))
    lic["signature"] = base64.b64encode(sig).decode()
    return lic


# --------------------------------------------------------------------------- #
# Client-side verification (uses the PUBLIC key only)
# --------------------------------------------------------------------------- #
def verify_license(lic: dict, public_key_hex: str,
                   fingerprint: str | None = None) -> None:
    """Raise LicenseError unless the license is valid for this machine/date."""
    _require_crypto()
    if not public_key_hex:
        raise LicenseError("No public key configured in config.LICENSE_PUBLIC_KEY.")
    sig_b64 = lic.get("signature")
    if not sig_b64:
        raise LicenseError("License has no signature.")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        pub.verify(base64.b64decode(sig_b64), _canonical_payload(lic))
    except (InvalidSignature, ValueError):
        raise LicenseError("License signature is invalid (not issued by the owner).")

    fp = fingerprint or machine_fingerprint()
    if lic.get("fingerprint") != fp:
        raise LicenseError(
            "License is not valid for this machine.\n"
            f"  This machine fingerprint: {fp}\n"
            f"  Licensed fingerprint:     {lic.get('fingerprint')}\n"
            "  Send the first value to the licensor to obtain a license.")

    try:
        exp = datetime.strptime(lic["expires"], "%Y-%m-%d").date()
    except Exception:
        raise LicenseError("License expiry date is malformed.")
    if date.today() > exp:
        raise LicenseError(f"License expired on {lic['expires']}.")


def load_license(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        raise LicenseError(f"License file not found: {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise LicenseError(f"License file is not valid JSON: {exc}")


def enforce(config) -> dict | None:
    """Entry point used at startup. Returns the license dict if valid.

    Honours config.LICENSE_ENFORCE. Raises LicenseError on any problem so the
    caller can refuse to start.
    """
    if not getattr(config, "LICENSE_ENFORCE", False):
        return None
    if not _HAVE_CRYPTO:
        raise LicenseError("The 'cryptography' package is required for licensing. "
                           "Install dependencies first.")
    lic = load_license(getattr(config, "LICENSE_FILE", "license.key"))
    verify_license(lic, getattr(config, "LICENSE_PUBLIC_KEY", ""))
    return lic


def _require_crypto() -> None:
    if not _HAVE_CRYPTO:
        raise LicenseError("The 'cryptography' package is not installed.")
