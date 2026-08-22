"""TRACE record construction for SOVP attestation results."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TRACE_REQUIRED_FIELDS = (
    "trace_id",
    "agent_id",
    "agent_manifest_id",
    "manifest_verification_result",
    "tool_id",
    "policy_hash",
    "catalog_hash",
    "decision",
    "decision_reason",
    "payload_classification",
    "egress_destination",
    "hitl_required",
    "hitl_approval_id",
    "timestamp",
    "tee_measurement",
)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return deterministic JSON bytes for TRACE signing."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64url_no_padding(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def build_trace_record(sovp_result: Mapping[str, Any]) -> dict[str, Any]:
    """Build an unsigned TRACE envelope from a SOVP result document."""

    agentrust = sovp_result.get("agentrust")
    if not isinstance(agentrust, Mapping):
        raise ValueError("SOVP result must contain an 'agentrust' object")

    missing = [field for field in TRACE_REQUIRED_FIELDS if field not in agentrust]
    if missing:
        raise ValueError(f"missing TRACE fields: {', '.join(missing)}")

    record = {field: agentrust[field] for field in TRACE_REQUIRED_FIELDS}
    record["sovp_evidence"] = sovp_result.get("sovp", {})
    record["signature"] = ""
    return record


def trace_signing_pre_image(record: Mapping[str, Any]) -> bytes:
    """Return the canonical signing pre-image for a TRACE record."""

    covered = {key: value for key, value in record.items() if key != "signature"}
    return _canonical_json(covered)


def sign_trace_record(record: Mapping[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Return a signed TRACE record."""

    signed = dict(record)
    signed["signature"] = _b64url_no_padding(private_key.sign(trace_signing_pre_image(signed)))
    return signed
