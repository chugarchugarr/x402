"""Signing helpers extracted from the pinned RLP-1 implementation.

Only the signing and canonicalization code required by RLP-1 is retained.
Pinned source: 2a2b11f905acd7a1d3dd430ff81ed279c350e6a4.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTOCOL = "resolution-receipt/0.1"
SIGNATURE_DOMAIN = b"resolution-receipt/signed-object/v1\n"
ED25519_MULTICODEC = b"\xed\x01"
BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReceiptError(ValueError):
    """Raised when an artifact violates the public receipt contract."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def _reject_float(value: str) -> Any:
    raise ReceiptError(f"floating-point JSON numbers are not allowed: {value}")

def _reject_constant(value: str) -> Any:
    raise ReceiptError(f"non-finite JSON value is not allowed: {value}")

def _validate_text(value: str) -> None:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ReceiptError("unpaired Unicode surrogate is not allowed")

def validate_json(value: Any) -> None:
    """Reject values whose serialization is ambiguous across implementations."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise ReceiptError("integer exceeds the interoperable JSON range")
        return
    if isinstance(value, float):
        raise ReceiptError("floating-point JSON numbers are not allowed")
    if isinstance(value, str):
        _validate_text(value)
        return
    if isinstance(value, list):
        for item in value:
            validate_json(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReceiptError("JSON object keys must be strings")
            _validate_text(key)
            validate_json(item)
        return
    raise ReceiptError(f"unsupported JSON value: {type(value).__name__}")

def load_json(path: str | os.PathLike[str]) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_pairs,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
    )
    validate_json(value)
    return value

def canonical_bytes(value: Any) -> bytes:
    validate_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

def write_json(
    path: str | os.PathLike[str], value: Any, *, private: bool = False
) -> None:
    validate_json(value)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = 0o600 if private else 0o644
    descriptor = os.open(destination, flags, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
    except Exception:
        destination.unlink(missing_ok=True)
        raise

def hash_object(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()

def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ReceiptError("invalid base64url value")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ReceiptError("invalid base64url value") from exc
    if _b64url_encode(decoded) != value:
        raise ReceiptError("non-canonical base64url value")
    return decoded

def _base58_encode(value: bytes) -> str:
    leading_zeroes = len(value) - len(value.lstrip(b"\x00"))
    number = int.from_bytes(value, "big")
    encoded = bytearray()
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(BASE58_ALPHABET[remainder])
    encoded.reverse()
    return (BASE58_ALPHABET[:1] * leading_zeroes + encoded).decode("ascii")

def _base58_decode(value: str) -> bytes:
    if not value:
        raise ReceiptError("empty base58 value")
    index = {chr(char): position for position, char in enumerate(BASE58_ALPHABET)}
    number = 0
    try:
        for char in value:
            number = number * 58 + index[char]
    except KeyError as exc:
        raise ReceiptError("invalid base58 character") from exc
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + raw

def did_from_public_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ReceiptError("Ed25519 public key must be 32 bytes")
    return "did:key:z" + _base58_encode(ED25519_MULTICODEC + public_key)

def public_key_from_did(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ReceiptError("expected a did:key with base58btc multibase")
    decoded = _base58_decode(did[len("did:key:z") :])
    if not decoded.startswith(ED25519_MULTICODEC):
        raise ReceiptError("DID is not an Ed25519 did:key")
    public_key = decoded[len(ED25519_MULTICODEC) :]
    if len(public_key) != 32:
        raise ReceiptError("Ed25519 did:key has the wrong length")
    if did_from_public_key(public_key) != did:
        raise ReceiptError("non-canonical did:key")
    return public_key

def _raw_private_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

def create_key(path: str | os.PathLike[str], *, label: str) -> str:
    if not label or len(label) > 80:
        raise ReceiptError("key label must contain 1 to 80 characters")
    private_key = Ed25519PrivateKey.generate()
    did = did_from_public_key(_raw_public_key(private_key))
    write_json(
        path,
        {
            "algorithm": "Ed25519",
            "did": did,
            "label": label,
            "private_key": _b64url_encode(_raw_private_key(private_key)),
        },
        private=True,
    )
    return did

def _load_private_key(path: str | os.PathLike[str]) -> tuple[Ed25519PrivateKey, str]:
    data = load_json(path)
    if not isinstance(data, dict) or data.get("algorithm") != "Ed25519":
        raise ReceiptError("unsupported private key file")
    raw = _b64url_decode(data.get("private_key", ""))
    if len(raw) != 32:
        raise ReceiptError("Ed25519 private key must be 32 bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(raw)
    did = did_from_public_key(_raw_public_key(private_key))
    if data.get("did") != did:
        raise ReceiptError("private key file DID does not match its key")
    return private_key, did

def _signature_message(kind: str, payload: Any) -> bytes:
    if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", kind):
        raise ReceiptError("invalid signed object kind")
    return SIGNATURE_DOMAIN + kind.encode("ascii") + b"\n" + canonical_bytes(payload)

def sign_envelope(
    kind: str, payload: Any, key_path: str | os.PathLike[str]
) -> dict[str, Any]:
    private_key, did = _load_private_key(key_path)
    signature = private_key.sign(_signature_message(kind, payload))
    return {
        "kind": kind,
        "payload": payload,
        "protocol": PROTOCOL,
        "signature": _b64url_encode(signature),
        "signer": did,
    }

def verify_envelope(
    envelope: Any, *, expected_kind: str | None = None
) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise ReceiptError("signed object must be a JSON object")
    expected_fields = {"kind", "payload", "protocol", "signature", "signer"}
    if set(envelope) != expected_fields:
        raise ReceiptError("signed object has missing or unknown top-level fields")
    if envelope["protocol"] != PROTOCOL:
        raise ReceiptError("unsupported protocol")
    kind = envelope["kind"]
    if expected_kind is not None and kind != expected_kind:
        raise ReceiptError(f"expected kind {expected_kind}, found {kind}")
    public_key = Ed25519PublicKey.from_public_bytes(
        public_key_from_did(envelope["signer"])
    )
    signature = _b64url_decode(envelope["signature"])
    if len(signature) != 64:
        raise ReceiptError("Ed25519 signature must be 64 bytes")
    try:
        public_key.verify(signature, _signature_message(kind, envelope["payload"]))
    except InvalidSignature as exc:
        raise ReceiptError("invalid Ed25519 signature") from exc
    return envelope["payload"]

