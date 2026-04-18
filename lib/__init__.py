"""
Library layer for DON-hosted secrets (encrypt + upload).

Designed to work without installation:
  - copy/download this folder
  - `pip install -r requirements.txt` (+ optional encrypt extras)
  - import from your code: `from lib.uploader import ...`
"""

from __future__ import annotations

__all__ = [
    "DEFAULT_GATEWAY_URLS",
    "upload_encrypted_secrets_to_don",
    "build_secrets_payload",
    "build_gateway_request_json",
    "format_curl_command",
    "format_curl_command_powershell",
    "encrypt_secrets",
]

from .uploader import (  # noqa: F401
    DEFAULT_GATEWAY_URLS,
    build_gateway_request_json,
    build_secrets_payload,
    format_curl_command,
    format_curl_command_powershell,
    upload_encrypted_secrets_to_don,
)


def encrypt_secrets(*args, **kwargs):
    """
    Lazy wrapper so upload can be used without encrypt dependencies.

    Install encrypt dependencies:
      - `pip install -r requirements-encrypt.txt`
    """

    try:
        from .encrypt import encrypt_secrets as _encrypt  # noqa: WPS433
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "encrypt_secrets() requires extra dependencies. Install with: pip install -r requirements-encrypt.txt"
        ) from exc
    return _encrypt(*args, **kwargs)

