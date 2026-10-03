# RJHex — Securing & Licensing the Tool

This portal supports two independent protections so only people **you** authorise
can run it:

1. **Portal login** — a username + password gate on the web portal.
2. **Machine-locked license** — a cryptographically signed license file bound to a
   specific machine and expiry date. Only you (holding the private key) can issue
   licenses; a copy on an unlicensed machine refuses to start.

Both are **off by default** so the tool works out of the box. Turn on whichever
you want in `config.py`.

> ### Honest limitation — read this
> RJHex ships as Python **source code**. Client-side licensing deters casual
> copying and sharing, but anyone technical enough can open the files and remove
> a check. There is no way around this for source-shipped software. For real
> protection, **ship a compiled binary** (see *Packaging* below) and keep the
> source private. Licensing + a compiled binary together is what commercial tools
> use.

---

## 1. Portal login (quick, simple)

Stops anyone opening the portal without your password.

1. Generate a hash of your chosen password:
   ```bash
   python -c "import hashlib;print(hashlib.sha256(b'YOUR-PASSWORD').hexdigest())"
   ```
2. In `config.py` set:
   ```python
   LOGIN_REQUIRED      = True
   LOGIN_USERNAME      = "admin"
   LOGIN_PASSWORD_HASH = "<paste the hash from step 1>"
   SESSION_SECRET      = "<any long random string>"   # keeps sessions across restarts
   ```
3. Restart. The portal now shows a sign-in page; the password is never stored in
   plain text.

---

## 2. Machine-locked license (strong binding)

A license is a signed file that says *"this licensee may run RJHex on this
machine until this date"*. It uses **Ed25519** signatures: your **private key
stays with you**; the app ships only the **public key** to verify. Nobody can
forge a license without your private key.

### One-time setup (you, the owner)

```bash
cd vapt-portal
python license_tool.py genkeys          # creates rjhex_private.key (KEEP SECRET)
```

It prints a **public key**. In `config.py` set:
```python
LICENSE_ENFORCE    = True
LICENSE_PUBLIC_KEY = "<the public key it printed>"
```
Store `rjhex_private.key` somewhere safe (password manager / offline). **Never**
put it on the USB stick or in git — `.gitignore` already excludes it.

### Giving someone access

1. On **their** machine they run:
   ```bash
   python license_tool.py fingerprint
   ```
   and send you the string (e.g. `587274eb4c1abffb38ab9e0b03ebf2c8`).

2. On **your** machine you issue a license for that fingerprint:
   ```bash
   python license_tool.py issue --licensee "Acme Corp" \
       --fingerprint 587274eb4c1abffb38ab9e0b03ebf2c8 \
       --days 365 --private rjhex_private.key --out license.key
   ```

3. Send them `license.key`. They drop it next to `app.py`. Done — it only works
   on their machine, only until it expires.

### What happens without a valid license
The portal **refuses to start** and prints the reason (missing / wrong machine /
expired), along with the machine's fingerprint so the user can request one.

To check a license on a machine:
```bash
python license_tool.py verify --file license.key
```

---

## 3. Packaging as a binary (recommended for real distribution)

Compiling removes the editable `.py` files, making the licensing check far
harder to bypass.

```bash
pip install pyinstaller
cd vapt-portal
pyinstaller --onefile --name RJHex \
  --add-data "templates:templates" \
  --add-data "static:static" \
  --add-data "report/assets:report/assets" \
  app.py
```

(On Windows use `;` instead of `:` in `--add-data`.) You get a single
`dist/RJHex` (or `RJHex.exe`) that users run directly — no Python install
needed, and the source isn't sitting there to edit. Keep `LICENSE_ENFORCE=True`
baked in before you build. For extra hardening, obfuscate first with a tool like
`pyarmor`.

---

## Recommended setup for "only my people can run it"

| Goal | Do this |
|------|---------|
| Keep it simple, trusted users | Login only (section 1) |
| Stop copies running elsewhere | Login + machine license (1 + 2) |
| Distribute to clients / sell | Login + license + **compiled binary** (1 + 2 + 3) |

## Files involved
- `config.py` — all the switches (`LOGIN_*`, `LICENSE_*`).
- `license_tool.py` — your CLI to make keys and issue licenses.
- `security/licensing.py` — verification logic used at startup.
- `rjhex_private.key` — **your secret** (gitignored, never ship).
- `license.key` — per-user license you issue (gitignored).
