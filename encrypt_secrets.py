from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


def _require(value: Optional[str], name: str) -> str:
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _load_env_first(argv: Optional[list[str]]) -> None:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", default=os.getenv("ENV_FILE", ".env"))
    pre_args, _ = pre.parse_known_args(argv)
    env_path = Path(pre_args.env_file)
    if env_path.exists():
        load_dotenv(env_path)


def main(argv: Optional[list[str]] = None) -> int:
    _load_env_first(argv)

    # Lazy import so this script still shows help without encrypt deps installed
    try:
        from lib.encrypt import encrypt_secrets
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "encrypt_secrets.py requires extra dependencies. Install: pip install -r requirements-encrypt.txt"
        ) from exc

    p = argparse.ArgumentParser(description="Encrypt secrets JSON into encryptedSecretsHexstring (ECIES + TDH2).")
    p.add_argument("--env-file", default=os.getenv("ENV_FILE", ".env"), help="Path to .env (default: .env)")

    p.add_argument("--secrets-json", default=os.getenv("CHAINLINK_SECRETS_JSON", "secrets.json"))
    p.add_argument("--private-key", default=os.getenv("PRIVATE_KEY") or os.getenv("DEPLOYER_PRIVATE_KEY"))
    p.add_argument("--rpc-url", default=os.getenv("WEB3_RPC_URL") or os.getenv("ETHEREUM_SEPOLIA_RPC_URL"))
    p.add_argument("--functions-router-address", default=os.getenv("CHAINLINK_ROUTER_ADDRESS"))
    p.add_argument("--don-id", default=os.getenv("CHAINLINK_DON_ID_TEXT", "fun-ethereum-sepolia-1"))
    p.add_argument("--out-prefix", default=os.getenv("CHAINLINK_ENC_OUT_PREFIX", "enc_artifacts"))
    args = p.parse_args(argv)

    artifacts = encrypt_secrets(
        secrets_json_path=_require(args.secrets_json, "secrets json path"),
        private_key_hex=_require(args.private_key, "private key"),
        rpc_url=_require(args.rpc_url, "rpc url"),
        functions_router_address=_require(args.functions_router_address, "functions router address"),
        don_id=_require(args.don_id, "don id"),
        out_prefix=args.out_prefix,
    )

    print(f"Coordinator: {artifacts.coordinator_address}")
    print(f"DON ID: {artifacts.don_id}")
    if artifacts.out_prefix is not None:
        pfx = artifacts.out_prefix
        print(f"Signed secrets: {pfx.with_suffix('.signed_secrets.json')}")
        print(f"DON-key encrypted payload: {pfx.with_suffix('.don_key_encrypted.json')}")
        print(f"TDH2 encrypted JSON: {pfx.with_suffix('.encrypted_secrets.json')}")
        print(f"encryptedSecretsHexstring file: {pfx.with_suffix('.encrypted_secrets.hex.txt')}")
    print(f"encryptedSecretsHexstring: {artifacts.encrypted_secrets_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

