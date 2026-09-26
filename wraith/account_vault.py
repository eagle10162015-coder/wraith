"""Local encrypted account import for agent browser sessions.

Only account metadata and opaque fill capabilities leave this module. Passwords
are encrypted on disk with an AES-GCM key held by the operating-system keyring.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import secrets as os_secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .secrets import (
    SecretCapability,
    SecretMaterial,
    SecretPolicyError,
    SecretRequestContext,
    canonical_origin,
    register_secret_provider,
)

_KEYRING_SERVICE = "wraith-agent-account-vault"
_KEYRING_USER = "local-vault-key"
_VERSION = 1


def _vault_path() -> Path:
    configured = os.environ.get("WRAITH_VAULT_PATH")
    return Path(configured).expanduser() if configured else Path.home() / ".wraith" / "accounts.vault"


def _key() -> bytes:
    import keyring

    encoded = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USER)
    if encoded:
        key = base64.b64decode(encoded, validate=True)
        if len(key) != 32:
            raise ValueError("Invalid key in OS keyring")
        return key
    key = AESGCM.generate_key(bit_length=256)
    keyring.set_password(_KEYRING_SERVICE, _KEYRING_USER, base64.b64encode(key).decode("ascii"))
    return key


def _load() -> list[dict[str, str]]:
    path = _vault_path()
    if not path.exists():
        return []
    blob = json.loads(path.read_text(encoding="utf-8"))
    if blob.get("version") != _VERSION:
        raise ValueError("Unsupported vault version")
    plaintext = AESGCM(_key()).decrypt(
        base64.b64decode(blob["nonce"]),
        base64.b64decode(blob["ciphertext"]),
        b"wraith-account-vault-v1",
    )
    records = json.loads(plaintext)
    if not isinstance(records, list):
        raise ValueError("Invalid vault contents")
    return records


def _save(records: list[dict[str, str]]) -> None:
    path = _vault_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    nonce = os_secrets.token_bytes(12)
    ciphertext = AESGCM(_key()).encrypt(
        nonce, json.dumps(records, ensure_ascii=False).encode("utf-8"), b"wraith-account-vault-v1"
    )
    blob = {
        "version": _VERSION,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    fd, tmp_name = tempfile.mkstemp(prefix=".accounts-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(blob, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def import_google_csv(paths: list[str], *, source: str = "google") -> dict[str, int]:
    """Merge Google Password Manager CSV exports without discarding other accounts."""
    records = _load()
    existing = {(r["origin"], r["username"], r["source"]): i for i, r in enumerate(records)}
    imported = updated = skipped = 0
    for file_name in paths:
        with open(file_name, newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            fields = set(reader.fieldnames or ())
            if not {"url", "username", "password"}.issubset(fields):
                raise ValueError(f"{Path(file_name).name}: expected url,username,password columns")
            for row in reader:
                try:
                    origin = canonical_origin(row["url"])
                except (SecretPolicyError, TypeError):
                    skipped += 1
                    continue
                username = (row.get("username") or "").strip()
                password = row.get("password") or ""
                if not username or not password:
                    skipped += 1
                    continue
                identity = (origin, username, source)
                record = {
                    "id": os_secrets.token_hex(16),
                    "origin": origin,
                    "username": username,
                    "password": password,
                    "name": row.get("name") or urlsplit(origin).hostname or origin,
                    "source": source,
                }
                index = existing.get(identity)
                if index is None:
                    existing[identity] = len(records)
                    records.append(record)
                    imported += 1
                else:
                    record["id"] = records[index]["id"]
                    records[index] = record
                    updated += 1
    if imported or updated:
        _save(records)
    return {"imported": imported, "updated": updated, "skipped": skipped}


def accounts_for(url: str) -> list[dict[str, str]]:
    origin = canonical_origin(url)
    return [
        {key: r[key] for key in ("id", "origin", "username", "name", "source")}
        for r in _load() if r["origin"] == origin
    ]


def all_accounts() -> list[dict[str, str]]:
    return [
        {key: r[key] for key in ("id", "origin", "username", "name", "source")}
        for r in _load()
    ]


def upsert_account(
    url: str, username: str, password: str, *, name: str = "", source: str = "agent", account_id: str = ""
) -> dict[str, str]:
    origin = canonical_origin(url)
    if not username or not password:
        raise ValueError("Username and password are required")
    records = _load()
    if account_id:
        record = next((r for r in records if r["id"] == account_id), None)
        if record is None or record["origin"] != origin or record["username"] != username:
            raise ValueError("Account ID does not match origin and username")
    else:
        record = next((r for r in records if (r["origin"], r["username"], r["source"]) == (origin, username, source)), None)
    if record is None:
        record = {"id": os_secrets.token_hex(16), "origin": origin, "username": username, "source": source}
        records.append(record)
    record["password"] = password
    record["name"] = name or urlsplit(origin).hostname or origin
    _save(records)
    return {key: record[key] for key in ("id", "origin", "username", "name", "source")}


def delete_account(account_id: str) -> bool:
    records = _load()
    remaining = [r for r in records if r["id"] != account_id]
    if len(remaining) == len(records):
        return False
    _save(remaining)
    return True


def capability_for(account_id: str, field_kind: str) -> dict[str, object]:
    if field_kind not in {"username", "password"}:
        raise ValueError("field_kind must be username or password")
    record = next((r for r in _load() if r["id"] == account_id), None)
    if record is None:
        raise KeyError("Unknown account")
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    nonce = os_secrets.token_hex(16)
    message = f"{record['id']}:{field_kind}:{int(expires.timestamp())}:{nonce}"
    signature = hmac.new(_key(), message.encode("ascii"), hashlib.sha256).hexdigest()
    cap = SecretCapability(
        provider="account-vault",
        handle=f"{message}:{signature}",
        allowed_origins=(record["origin"],),
        field_kind=field_kind,
        expires_at=expires,
        max_uses=1,
    )
    return {
        "provider": cap.provider,
        "handle": cap.handle,
        "allowed_origins": list(cap.allowed_origins),
        "field_kind": cap.field_kind,
        "expires_at": cap.expires_at.isoformat() if cap.expires_at else None,
        "max_uses": cap.max_uses,
    }


def _reveal_for_browser(account_id: str, field_kind: str, url: str) -> str:
    """Internal adapter boundary; never return this value from an agent tool."""
    if field_kind not in {"username", "password"}:
        raise ValueError("Invalid field kind")
    record = next((r for r in _load() if r["id"] == account_id), None)
    if record is None or record["origin"] != canonical_origin(url):
        raise SecretPolicyError("Account does not match browser origin")
    return record[field_kind]


class AccountVaultProvider:
    def resolve(self, capability: SecretCapability, context: SecretRequestContext) -> SecretMaterial:
        parts = capability.handle.split(":")
        if len(parts) != 5:
            raise SecretPolicyError("Invalid account capability")
        account_id, field, expiry_text, nonce, signature = parts
        message = ":".join(parts[:4])
        expected = hmac.new(_key(), message.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected) or field != capability.field_kind:
            raise SecretPolicyError("Invalid account capability")
        try:
            expiry = int(expiry_text)
        except ValueError as exc:
            raise SecretPolicyError("Invalid account capability") from exc
        if datetime.now(timezone.utc).timestamp() >= expiry:
            raise SecretPolicyError("Expired account capability")
        record = next((r for r in _load() if r["id"] == account_id), None)
        if record is None or record["origin"] != canonical_origin(context.origin):
            raise SecretPolicyError("Account does not match page origin")
        if canonical_origin(context.frame_origin) != record["origin"]:
            raise SecretPolicyError("Account does not match field frame origin")
        return SecretMaterial(record[field])


def register() -> None:
    register_secret_provider("account-vault", AccountVaultProvider(), replace=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import Google Password Manager exports into the encrypted Wraith vault")
    sub = parser.add_subparsers(dest="command", required=True)
    importing = sub.add_parser("import-google")
    importing.add_argument("csv", nargs="+")
    importing.add_argument("--source", default="google", help="Label identifying the Google account or export")
    listing = sub.add_parser("list")
    listing.add_argument("url")
    sub.add_parser("list-all")
    sub.add_parser("_upsert_json", help=argparse.SUPPRESS)
    deleting = sub.add_parser("delete")
    deleting.add_argument("account_id")
    internal = sub.add_parser("_browser_reveal", help=argparse.SUPPRESS)
    internal.add_argument("account_id")
    internal.add_argument("field_kind", choices=("username", "password"))
    internal.add_argument("url")
    args = parser.parse_args()
    if args.command == "import-google":
        print(json.dumps(import_google_csv(args.csv, source=args.source)))
    elif args.command == "list":
        print(json.dumps(accounts_for(args.url)))
    elif args.command == "list-all":
        print(json.dumps(all_accounts()))
    elif args.command == "_upsert_json":
        payload = json.loads(sys.stdin.read(1024 * 1024))
        print(json.dumps(upsert_account(payload["url"], payload["username"], payload["password"], name=payload.get("name", ""), source=payload.get("source", "agent"), account_id=payload.get("account_id", ""))))
    elif args.command == "delete":
        print(json.dumps({"deleted": delete_account(args.account_id)}))
    elif args.command == "_browser_reveal":
        print(_reveal_for_browser(args.account_id, args.field_kind, args.url), end="")


if __name__ == "__main__":
    main()
