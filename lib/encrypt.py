from __future__ import annotations

import base64
import hashlib
import json
import secrets as py_secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from ecdsa import NIST256p, ellipticcurve
from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, padding as crypto_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from web3 import Web3


TDH2_INPUT_SIZE = 32
GROUP_NAME = "P256"


ROUTER_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "id", "type": "bytes32"}],
        "name": "getContractById",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]

COORDINATOR_ABI = [
    {
        "inputs": [],
        "name": "getThresholdPublicKey",
        "outputs": [{"internalType": "bytes", "name": "", "type": "bytes"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getDONPublicKey",
        "outputs": [{"internalType": "bytes", "name": "", "type": "bytes"}],
        "stateMutability": "view",
        "type": "function",
    },
]


@dataclass(frozen=True)
class EncryptionArtifacts:
    coordinator_address: str
    don_id: str
    signed_secrets_json: str
    don_key_encrypted_json: str
    encrypted_secrets_json: str
    encrypted_secrets_hex: str
    out_prefix: Optional[Path] = None


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _load_secrets_map_from_path(path: str | Path) -> Dict[str, str]:
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict) or not data:
        raise ValueError("Secrets JSON must be a non-empty object map")
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("Secrets JSON must be string->string map")
    return data


def _sign_message_text(private_key_hex: str, message_text: str) -> str:
    acct = Account.from_key(private_key_hex)
    signed = acct.sign_message(encode_defunct(text=message_text))
    return signed.signature.hex().removeprefix("0x")


def _format_bytes32_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 32:
        raise ValueError("don id must be <= 32 bytes")
    return raw + b"\x00" * (32 - len(raw))


def fetch_don_keys(
    *,
    rpc_url: str,
    functions_router_address: str,
    don_id_text: str,
) -> Tuple[str, Dict[str, Any], str]:
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise ValueError("web3 connection failed")

    router = w3.eth.contract(address=Web3.to_checksum_address(functions_router_address), abi=ROUTER_ABI)
    don_id_bytes32 = _format_bytes32_string(don_id_text)
    coordinator_address = router.functions.getContractById(don_id_bytes32).call()

    coordinator = w3.eth.contract(address=Web3.to_checksum_address(coordinator_address), abi=COORDINATOR_ABI)
    threshold_public_key_bytes = coordinator.functions.getThresholdPublicKey().call()
    don_public_key_hex = coordinator.functions.getDONPublicKey().call().hex()

    threshold_public_key = json.loads(bytes(threshold_public_key_bytes).decode("utf-8"))
    return coordinator_address, threshold_public_key, don_public_key_hex


def _ensure_uncompressed_pubkey_65(pub_hex: str) -> bytes:
    clean = pub_hex.removeprefix("0x")
    raw = bytes.fromhex(clean)
    if len(raw) == 64:
        return b"\x04" + raw
    if len(raw) == 65 and raw[0] == 0x04:
        return raw
    if len(raw) == 33:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw)
        return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    raise ValueError("Unsupported public key length for DON public key")


def _ethcrypto_encrypt_with_public_key(public_key_hex: str, message: bytes) -> str:
    recipient_pub_uncompressed = _ensure_uncompressed_pubkey_65(public_key_hex)
    recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), recipient_pub_uncompressed)

    ephem_priv = ec.generate_private_key(ec.SECP256K1())
    ephem_pub = ephem_priv.public_key()
    ephem_pub_uncompressed = ephem_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    ephem_pub_compressed = ephem_pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

    shared_secret = ephem_priv.exchange(ec.ECDH(), recipient_pub)
    if len(shared_secret) != 32:
        shared_secret = shared_secret.rjust(32, b"\x00")[-32:]

    kdf_hash = hashlib.sha512(shared_secret).digest()
    enc_key = kdf_hash[:32]
    mac_key = kdf_hash[32:]

    iv = py_secrets.token_bytes(16)
    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
    h.update(iv + ephem_pub_uncompressed + ciphertext)
    mac = h.finalize()

    # EthCrypto.cipher.stringify: iv(16) + ephemPublicKeyCompressed(33) + mac(32) + ciphertext
    return (iv + ephem_pub_compressed + mac + ciphertext).hex()


def _decode_p256_point_b64(point_b64: str):
    point_bytes = base64.b64decode(point_b64)
    return ellipticcurve.Point.from_bytes(NIST256p.curve, point_bytes, validate_encoding=True)


def _encode_p256_point_b64(point) -> str:
    point_bytes = ellipticcurve.Point.to_bytes(point, encoding="uncompressed")
    return base64.b64encode(point_bytes).decode("utf-8")


def _concatenate_points(points) -> bytes:
    out = GROUP_NAME
    for p in points:
        out += "," + ellipticcurve.Point.to_bytes(p, encoding="uncompressed").hex()
    return out.encode("utf-8")


def _hash1(point) -> bytes:
    return hashlib.sha256(b"tdh2hash1" + _concatenate_points([point])).digest()


def _hash2(msg: bytes, label: bytes, p1, p2, p3, p4) -> int:
    if len(msg) != TDH2_INPUT_SIZE:
        raise ValueError("msg must be 32 bytes")
    if len(label) != TDH2_INPUT_SIZE:
        raise ValueError("label must be 32 bytes")

    digest = hashlib.sha256(
        b"tdh2hash2" + msg + label + _concatenate_points([p1, p2, p3, p4])
    ).digest()
    return int.from_bytes(digest, "big") % NIST256p.order


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def _tdh2_encrypt(pub: dict, msg32: bytes, label32: bytes) -> str:
    if pub.get("Group") != GROUP_NAME:
        raise ValueError("invalid TDH2 group")
    if len(msg32) != TDH2_INPUT_SIZE or len(label32) != TDH2_INPUT_SIZE:
        raise ValueError("TDH2 input size must be 32 bytes")

    g_bar = _decode_p256_point_b64(pub["G_bar"])
    h_point = _decode_p256_point_b64(pub["H"])

    n = NIST256p.order
    G = NIST256p.generator
    r = py_secrets.randbelow(n - 1) + 1
    s = py_secrets.randbelow(n - 1) + 1

    c = _xor_bytes(_hash1(h_point * r), msg32)
    u = G * r
    w = G * s
    u_bar = g_bar * r
    w_bar = g_bar * s

    e = _hash2(c, label32, u, w, u_bar, w_bar)
    f = (s + (r * e) % n) % n

    out = {
        "Group": GROUP_NAME,
        "C": base64.b64encode(c).decode("utf-8"),
        "Label": base64.b64encode(label32).decode("utf-8"),
        "U": _encode_p256_point_b64(u),
        "U_bar": _encode_p256_point_b64(u_bar),
        "E": base64.b64encode(e.to_bytes(32, "big")).decode("utf-8"),
        "F": base64.b64encode(f.to_bytes(32, "big")).decode("utf-8"),
    }
    return _canonical_json(out)


def _tdh2_hybrid_encrypt(pub: dict, plaintext: bytes) -> str:
    key = py_secrets.token_bytes(TDH2_INPUT_SIZE)
    nonce = py_secrets.token_bytes(12)
    sym_with_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    tdh2_ctxt_json = _tdh2_encrypt(pub, key, b"\x00" * TDH2_INPUT_SIZE)

    out = {
        "TDH2Ctxt": base64.b64encode(tdh2_ctxt_json.encode("utf-8")).decode("utf-8"),
        "SymCtxt": base64.b64encode(sym_with_tag).decode("utf-8"),
        "Nonce": base64.b64encode(nonce).decode("utf-8"),
    }
    return _canonical_json(out)


def encrypt_secrets(
    *,
    secrets_map: Optional[Dict[str, str]] = None,
    secrets_json_path: Optional[str | Path] = None,
    private_key_hex: str,
    rpc_url: str,
    functions_router_address: str,
    don_id: str = "fun-ethereum-sepolia-1",
    out_prefix: Optional[str | Path] = None,
) -> EncryptionArtifacts:
    if (secrets_map is None) == (secrets_json_path is None):
        raise ValueError("Provide exactly one of secrets_map or secrets_json_path")
    if not private_key_hex:
        raise ValueError("private_key_hex is required")
    if not rpc_url:
        raise ValueError("rpc_url is required")
    if not functions_router_address:
        raise ValueError("functions_router_address is required")

    if secrets_map is None:
        secrets_map = _load_secrets_map_from_path(secrets_json_path)  # type: ignore[arg-type]

    message = _canonical_json(secrets_map)
    signature = _sign_message_text(private_key_hex, message)
    signed_secrets_json = _canonical_json({"message": message, "signature": "0x" + signature})

    coordinator_address, threshold_pub, don_pub_hex = fetch_don_keys(
        rpc_url=rpc_url,
        functions_router_address=functions_router_address,
        don_id_text=don_id,
    )

    encrypted_signed_hex = _ethcrypto_encrypt_with_public_key(don_pub_hex, signed_secrets_json.encode("utf-8"))
    don_key_encrypted = {"0x0": base64.b64encode(bytes.fromhex(encrypted_signed_hex)).decode("utf-8")}
    don_key_encrypted_json = _canonical_json(don_key_encrypted)

    encrypted_secrets_json = _tdh2_hybrid_encrypt(threshold_pub, don_key_encrypted_json.encode("utf-8"))
    encrypted_secrets_hex = "0x" + encrypted_secrets_json.encode("utf-8").hex()

    prefix_path: Optional[Path] = None
    if out_prefix is not None:
        prefix_path = Path(out_prefix)
        prefix_path.parent.mkdir(parents=True, exist_ok=True)
        prefix_path.with_suffix(".signed_secrets.json").write_text(signed_secrets_json, encoding="utf-8")
        prefix_path.with_suffix(".don_key_encrypted.json").write_text(don_key_encrypted_json, encoding="utf-8")
        prefix_path.with_suffix(".encrypted_secrets.json").write_text(encrypted_secrets_json, encoding="utf-8")
        prefix_path.with_suffix(".encrypted_secrets.hex.txt").write_text(encrypted_secrets_hex, encoding="utf-8")

    return EncryptionArtifacts(
        coordinator_address=coordinator_address,
        don_id=don_id,
        signed_secrets_json=signed_secrets_json,
        don_key_encrypted_json=don_key_encrypted_json,
        encrypted_secrets_json=encrypted_secrets_json,
        encrypted_secrets_hex=encrypted_secrets_hex,
        out_prefix=prefix_path,
    )

