from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from lib.uploader import DEFAULT_GATEWAY_URLS, parse_gateway_urls, upload_encrypted_secrets_to_don


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

    p = argparse.ArgumentParser(description="Upload encrypted DON-hosted secrets (gateway secrets_set).")
    p.add_argument("--env-file", default=os.getenv("ENV_FILE", ".env"), help="Path to .env (default: .env)")

    p.add_argument("--private-key", default=os.getenv("PRIVATE_KEY") or os.getenv("DEPLOYER_PRIVATE_KEY"))
    p.add_argument("--don-id", default=os.getenv("CHAINLINK_DON_ID_TEXT", "fun-ethereum-sepolia-1"))
    p.add_argument("--gateway-urls", default=os.getenv("CHAINLINK_GATEWAY_URLS", ",".join(DEFAULT_GATEWAY_URLS)))
    p.add_argument("--slot-id", default=os.getenv("CHAINLINK_SECRETS_SLOT_ID", "0"))
    p.add_argument("--encrypted-secrets-hex", default=os.getenv("CHAINLINK_ENCRYPTED_SECRETS_HEX", ""))
    p.add_argument("--minutes-until-expiration", default=os.getenv("CHAINLINK_SECRETS_TTL_MIN", "60"))
    p.add_argument("--message-id", default=os.getenv("CHAINLINK_SECRETS_MESSAGE_ID", ""))
    p.add_argument("--version", default=os.getenv("CHAINLINK_SECRETS_VERSION", ""))
    p.add_argument("--expiration-ms", default=os.getenv("CHAINLINK_SECRETS_EXPIRATION_MS", ""))
    p.add_argument("--base-dir", default=os.getenv("CHAINLINK_BASE_DIR", ""))
    p.add_argument(
        "--debug",
        action="store_true",
        default=os.getenv("CHAINLINK_SECRETS_DEBUG", "").lower() in ("1", "true", "yes", "on"),
    )
    args = p.parse_args(argv)

    private_key = _require(args.private_key, "private key")
    don_id = _require(args.don_id, "don id")
    gateways = parse_gateway_urls(_require(args.gateway_urls, "gateway urls"))

    version_override = int(args.version) if args.version else None
    expiration_ms_override = int(args.expiration_ms) if args.expiration_ms else None

    base_dir = Path(args.base_dir).resolve() if args.base_dir else Path.cwd()

    summary = upload_encrypted_secrets_to_don(
        private_key_hex=private_key,
        don_id=don_id,
        gateway_urls=gateways,
        slot_id=int(args.slot_id),
        encrypted_secrets_hex_or_path=_require(args.encrypted_secrets_hex, "encrypted secrets hex"),
        minutes_until_expiration=int(args.minutes_until_expiration),
        message_id=(args.message_id.strip() or None) if args.message_id else None,
        version_override=version_override,
        expiration_ms_override=expiration_ms_override,
        base_dir=base_dir,
        debug=bool(args.debug),
    )

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

