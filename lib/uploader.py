from __future__ import annotations

import base64
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests
from eth_account import Account
from eth_account.messages import _hash_eip191_message
from eth_account.messages import encode_defunct

from .responses import (
    normalize_secrets_set_gateway_response,
    summarize_upload_encrypted_secrets_result,
)


MESSAGE_ID_MAX_LEN = 128
MESSAGE_METHOD_MAX_LEN = 64
MESSAGE_DON_ID_MAX_LEN = 64
MESSAGE_RECEIVER_LEN = 42  # 0x + 40 hex chars

# Match @chainlink/functions-toolkit examples (trailing slash).
DEFAULT_GATEWAY_URLS: Tuple[str, ...] = (
    "https://01.functions-gateway.testnet.chain.link/",
    "https://02.functions-gateway.testnet.chain.link/",
)


@dataclass(frozen=True)
class BuiltSecretsPayload:
    payload: Dict[str, Any]
    version: int
    expiration_ms: int
    storage_message_json: str
    signer_address: str


def random_message_id_uint32_str() -> str:
    # Match @chainlink/functions-toolkit:
    return str(random.randrange(0, 2**32))


def parse_gateway_urls(value: str | Sequence[str]) -> List[str]:
    if isinstance(value, str):
        raw_items = [s.strip() for s in value.split(",")]
        return [s for s in raw_items if s]
    return [str(s).strip() for s in value if str(s).strip()]


def _pad_bytes(value: str, length: int) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > length:
        raise ValueError(f"Value '{value}' is longer than max length {length}")
    return raw + b"\x00" * (length - len(raw))


def _gateway_message_body(message_id: str, method: str, don_id: str, receiver: str, payload: dict) -> bytes:
    payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return b"".join(
        [
            _pad_bytes(message_id, MESSAGE_ID_MAX_LEN),
            _pad_bytes(method, MESSAGE_METHOD_MAX_LEN),
            _pad_bytes(don_id, MESSAGE_DON_ID_MAX_LEN),
            _pad_bytes(receiver, MESSAGE_RECEIVER_LEN),
            payload_json,
        ]
    )


def sign_eip191_bytes(private_key_hex: str, payload_bytes: bytes) -> str:
    acct = Account.from_key(private_key_hex)
    signed = acct.sign_message(encode_defunct(payload_bytes))
    return signed.signature.hex().removeprefix("0x")


def is_hex_string(value: str) -> bool:
    raw = (value or "").strip()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        return False
    try:
        int(raw, 16)
    except ValueError:
        return False
    return len(raw) % 2 == 0


def normalize_encrypted_secrets_hex(value: str, *, base_dir: Optional[Path] = None) -> str:
    raw = (value or "").strip().strip('"').strip("'")
    if not raw:
        raise ValueError("encrypted secrets hex is empty")

    if is_hex_string(raw):
        return raw if raw.startswith("0x") else ("0x" + raw)

    p = Path(raw)
    if not p.is_absolute() and base_dir is not None:
        p = base_dir / p
    if p.exists() and p.is_file():
        file_raw = p.read_text(encoding="utf-8").strip().strip('"').strip("'")
        if not file_raw:
            raise ValueError(f"encrypted secrets file is empty: {p}")
        if not file_raw.startswith("0x"):
            file_raw = "0x" + file_raw
        if not is_hex_string(file_raw):
            raise ValueError(f"encrypted secrets file does not contain hex: {p}")
        return file_raw

    raise ValueError("encrypted secrets must be a hex string (0x...) or a path to a file containing it")


def build_secrets_payload(
    *,
    private_key_hex: str,
    slot_id: int,
    encrypted_secrets_hex: str,
    minutes_until_expiration: int,
    version_override: Optional[int] = None,
    expiration_ms_override: Optional[int] = None,
) -> BuiltSecretsPayload:
    if not encrypted_secrets_hex.startswith("0x"):
        raise ValueError("encrypted_secrets_hex must start with 0x")
    if minutes_until_expiration < 5:
        raise ValueError("minutes_until_expiration must be at least 5")

    acct = Account.from_key(private_key_hex)
    signer_address = acct.address

    signer_address_base64 = base64.b64encode(bytes.fromhex(signer_address[2:])).decode()
    encrypted_secrets_base64 = base64.b64encode(bytes.fromhex(encrypted_secrets_hex[2:])).decode()

    now_sec = int(time.time())
    now_ms = int(time.time() * 1000)
    secrets_version = int(version_override) if version_override is not None else now_sec
    secrets_expiration = (
        int(expiration_ms_override)
        if expiration_ms_override is not None
        else (now_ms + minutes_until_expiration * 60 * 1000)
    )

    storage_message = {
        "address": signer_address_base64,
        "slotid": int(slot_id),
        "payload": encrypted_secrets_base64,
        "version": int(secrets_version),
        "expiration": int(secrets_expiration),
    }
    storage_message_json = json.dumps(storage_message, separators=(",", ":"), ensure_ascii=False)

    storage_sig_hex = sign_eip191_bytes(private_key_hex, storage_message_json.encode("utf-8"))
    storage_signature_base64 = base64.b64encode(bytes.fromhex(storage_sig_hex)).decode()

    payload = {
        "slot_id": int(slot_id),
        "version": int(secrets_version),
        "payload": encrypted_secrets_base64,
        "expiration": int(secrets_expiration),
        "signature": storage_signature_base64,
    }

    return BuiltSecretsPayload(
        payload=payload,
        version=int(secrets_version),
        expiration_ms=int(secrets_expiration),
        storage_message_json=storage_message_json,
        signer_address=signer_address,
    )


def build_gateway_request_json(
    *,
    private_key_hex: str,
    don_id: str,
    payload: Dict[str, Any],
    message_id: str,
    receiver: str = "",
    method: str = "secrets_set",
    debug: bool = False,
) -> Tuple[str, Dict[str, Any]]:
    body = {
        "message_id": message_id,
        "method": method,
        "don_id": don_id,
        "receiver": receiver,
        "payload": payload,
    }

    gateway_message_bytes = _gateway_message_body(message_id, method, don_id, receiver, payload)
    gateway_sig_hex = sign_eip191_bytes(private_key_hex, gateway_message_bytes)
    gateway_signature = "0x" + gateway_sig_hex

    req = {
        "id": message_id,
        "jsonrpc": "2.0",
        "method": method,
        "params": {
            "body": body,
            "signature": gateway_signature,
        },
    }

    req_json = json.dumps(req, separators=(",", ":"), ensure_ascii=False)

    dbg: Dict[str, Any] = {}
    if debug:
        recovered = Account.recover_message(encode_defunct(gateway_message_bytes), signature=gateway_signature)
        msg_hash_hex = "0x" + _hash_eip191_message(encode_defunct(gateway_message_bytes)).hex()
        dbg = {
            "gateway_body_bytes_len": len(gateway_message_bytes),
            "gateway_eip191_hash": msg_hash_hex,
            "gateway_signature": gateway_signature,
            "gateway_signature_recovers": recovered,
            "http_request_body_len": len(req_json),
            "http_request_body": req_json,
        }

    return req_json, dbg


def format_curl_command(*, gateway_url: str, request_json: str) -> str:
    return (
        "curl -sS -X POST "
        + json.dumps(gateway_url)
        + " \\\n"
        + "  -H 'Content-Type: application/json' \\\n"
        + "  --data-binary @- <<'JSON'\n"
        + request_json
        + "\nJSON"
    )


def format_curl_command_powershell(*, gateway_url: str, request_json: str) -> str:
    return (
        "$body = @'\n"
        + request_json
        + "\n'@\n"
        + "$body | curl.exe -sS -X POST "
        + json.dumps(gateway_url)
        + " -H 'Content-Type: application/json' --data-binary @-"
    )


def post_gateway_json_rpc(
    *,
    gateway_url: str,
    request_json: str,
    timeout_s: int = 30,
    debug: bool = False,
) -> Dict[str, Any]:
    response = requests.post(
        gateway_url,
        data=request_json,
        headers={"Content-Type": "application/json"},
        timeout=timeout_s,
    )

    if debug:
        try:
            headers_json = json.dumps(dict(response.headers), indent=2, ensure_ascii=False)
        except Exception:
            headers_json = str(response.headers)
        print(f"\n[DEBUG] HTTP {response.status_code} from {gateway_url}")
        print("[DEBUG] Response headers:")
        print(headers_json)
        print("[DEBUG] Response body:")
        print(response.text)

    if response.status_code >= 400:
        try:
            body = response.json()
        except Exception:
            body = response.text
        raise RuntimeError(f"HTTP {response.status_code} from {gateway_url}: {body}")

    return response.json()


def upload_encrypted_secrets_to_don(
    *,
    private_key_hex: str,
    don_id: str,
    gateway_urls: Sequence[str] | str,
    slot_id: int,
    encrypted_secrets_hex_or_path: str,
    minutes_until_expiration: int = 60,
    message_id: Optional[str] = None,
    version_override: Optional[int] = None,
    expiration_ms_override: Optional[int] = None,
    base_dir: Optional[Path] = None,
    debug: bool = False,
) -> Dict[str, Any]:
    gateways = parse_gateway_urls(gateway_urls)
    if not gateways:
        raise ValueError("gateway_urls is empty")

    encrypted_hex = normalize_encrypted_secrets_hex(encrypted_secrets_hex_or_path, base_dir=base_dir)

    built = build_secrets_payload(
        private_key_hex=private_key_hex,
        slot_id=slot_id,
        encrypted_secrets_hex=encrypted_hex,
        minutes_until_expiration=minutes_until_expiration,
        version_override=version_override,
        expiration_ms_override=expiration_ms_override,
    )

    mid = (message_id or "").strip() or random_message_id_uint32_str()

    if debug:
        storage_sig = "0x" + sign_eip191_bytes(private_key_hex, built.storage_message_json.encode("utf-8"))
        storage_rec = Account.recover_message(
            encode_defunct(text=built.storage_message_json),
            signature=storage_sig,
        )
        print(f"[DEBUG] signer_address={built.signer_address}")
        print(f"[DEBUG] storage_signature_recovers={storage_rec}")
        print(f"[DEBUG] storage_message_json={built.storage_message_json}")

    last_err: Optional[Exception] = None

    for gw in gateways:
        try:
            req_json, dbg = build_gateway_request_json(
                private_key_hex=private_key_hex,
                don_id=don_id,
                payload=built.payload,
                message_id=mid,
                debug=debug,
            )
            if debug:
                print(f"\n[DEBUG] POST {gw} method=secrets_set message_id={mid}")
                for k, v in dbg.items():
                    print(f"[DEBUG] {k}={v}")
                print("[DEBUG] curl_command=")
                print(format_curl_command(gateway_url=gw, request_json=req_json))
                print("[DEBUG] curl_command_powershell=")
                print(format_curl_command_powershell(gateway_url=gw, request_json=req_json))

            result_json = post_gateway_json_rpc(
                gateway_url=gw,
                request_json=req_json,
                timeout_s=30,
                debug=debug,
            )

            normalized = normalize_secrets_set_gateway_response(gateway_url=gw, gateway_json=result_json)
            if not normalized.success:
                if debug:
                    print("[DEBUG] gateway payload.success=false; trying next gateway")
                continue

            return summarize_upload_encrypted_secrets_result(
                gateway_response=normalized,
                secrets_version=built.payload["version"],
            )
        except Exception as exc:
            last_err = exc
            continue

    if last_err is not None:
        raise RuntimeError(f"Failed to send secrets_set to all gateways. Last error: {last_err}") from last_err
    raise RuntimeError("Failed to send secrets_set to all gateways")

