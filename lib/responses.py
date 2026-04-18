from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class NodeResponse:
    success: bool
    error_message: Optional[str] = None


@dataclass(frozen=True)
class SecretsSetGatewayResponse:
    gateway_url: str
    # gateway-level success flag (result.body.payload.success)
    success: bool
    node_responses: List[NodeResponse]


def _get(obj: Any, path: List[str]) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            raise ValueError(f"Missing field: {'.'.join(path)}")
        cur = cur[key]
    return cur


def normalize_secrets_set_gateway_response(*, gateway_url: str, gateway_json: Dict[str, Any]) -> SecretsSetGatewayResponse:
    """
    Normalize a Chainlink Functions gateway JSON-RPC response for `secrets_set`.

    If the response is a JSON-RPC error, raises ValueError.
    """
    if "error" in gateway_json:
        err = gateway_json.get("error") or {}
        raise ValueError(
            f"gateway_error code={err.get('code')} message={err.get('message')} raw={gateway_json}"
        )

    payload = _get(gateway_json, ["result", "body", "payload"])
    if not isinstance(payload, dict):
        raise ValueError(f"Unexpected payload type: {type(payload)}")

    gateway_success = bool(payload.get("success", False))
    raw_node_responses = payload.get("node_responses") or []
    if not isinstance(raw_node_responses, list) or len(raw_node_responses) < 1:
        raise ValueError("Unexpected response: payload.node_responses is empty or not a list")

    node_responses: List[NodeResponse] = []
    for entry in raw_node_responses:
        try:
            node_payload = _get(entry, ["body", "payload"])
        except Exception:
            node_payload = {}
        node_success = bool(node_payload.get("success", False))
        node_err = node_payload.get("error_message")
        node_responses.append(
            NodeResponse(
                success=node_success,
                error_message=node_err if isinstance(node_err, str) else None,
            )
        )

    return SecretsSetGatewayResponse(
        gateway_url=gateway_url,
        success=gateway_success,
        node_responses=node_responses,
    )


def summarize_upload_encrypted_secrets_result(
    *,
    gateway_response: SecretsSetGatewayResponse,
    secrets_version: int,
) -> Dict[str, Any]:
    """
    Mirror toolkit semantics:
    - If ALL nodes failed -> raise
    - If SOME nodes failed -> return success=false (but still return version)
    - If ALL nodes succeeded -> success=true
    """
    total = len(gateway_response.node_responses)
    failed = sum(1 for nr in gateway_response.node_responses if not nr.success)

    if failed == total:
        raise RuntimeError("All nodes failed to store the encrypted secrets")

    return {
        "version": int(secrets_version),
        "success": failed == 0,
        "gatewayUrl": gateway_response.gateway_url,
        "nodeResponses": [
            {"success": nr.success, "error_message": nr.error_message}
            for nr in gateway_response.node_responses
        ],
    }

