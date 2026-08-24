"""TRACE record construction for SOVP attestation results.

Builds an AgenTrust TRACE v0.2 Trust Record from a SOVP attestation document and
signs it with the released ``agentrust-trace`` signing implementation, so the
output verifies under ``agentrust-trace-tests`` (TR-ENV / TR-SIG / TR-POL) at
Level 0.

Design stance: this bridge only *transcribes* a SOVP attestation into TRACE
shape. It measures nothing itself, so every field that would otherwise assert a
strong guarantee is set to its weakest honest value:

- ``runtime.platform`` is ``software-only`` (no hardware TEE in the bridge);
- ``origin.kind`` is ``third-party-control-plane`` (the evidence is asserted by
  SOVP, not measured by this runtime);
- ``appraisal.status`` is ``none`` (no verifier appraised the result);
- ``build_provenance.slsa_level`` is ``0`` (no build-provenance guarantee claimed).

This mirrors the project README's "What it does not claim" section: the record
never dresses transcribed evidence up as hardware-attested.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

from agentrust_trace.sign import TRACE_PROFILE_V0_2, sign_record
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Fields the caller must supply explicitly in the ``agentrust`` object. The bridge
# never infers an attestation claim it was not given.
TRACE_REQUIRED_FIELDS = (
    "agent_id",
    "policy_hash",
    "catalog_hash",
    "payload_classification",
    "tee_measurement",
)

# TR-POL-002 accepts only these; the model's fourth value ``declared`` passes the
# schema but fails Level-0 conformance, so it is deliberately not offered here.
_VALID_ENFORCEMENT_MODES = frozenset({"enforce", "advisory", "silent"})


def _enforcement_mode(agentrust: Mapping[str, Any]) -> str:
    """Return a conformance-valid ``policy.enforcement_mode`` for the record.

    Honest mapping from the caller's own governance decision:

    - an explicit ``policy_enforcement_mode`` wins, but must be one the TRACE
      conformance suite accepts;
    - otherwise, a caller ``decision`` that was acted on means the policy was
      *enforced*; with no decision at all the honest value is ``advisory`` (a
      policy is named but nothing is asserted to have acted on it).
    """
    mode = agentrust.get("policy_enforcement_mode")
    if mode is not None:
        if mode not in _VALID_ENFORCEMENT_MODES:
            raise ValueError(
                f"policy_enforcement_mode must be one of {sorted(_VALID_ENFORCEMENT_MODES)}, "
                f"got {mode!r} (the schema also allows 'declared', but it fails TRACE "
                "conformance TR-POL-002)"
            )
        return mode
    return "enforce" if agentrust.get("decision") else "advisory"


def build_trace_record(sovp_result: Mapping[str, Any]) -> dict[str, Any]:
    """Build an unsigned AgenTrust TRACE v0.2 Trust Record from a SOVP result.

    ``sovp_result`` must contain an ``agentrust`` object with the fields named in
    :data:`TRACE_REQUIRED_FIELDS` and may contain a ``sovp`` object with the source
    attestation payload. Missing required fields raise ``ValueError``; nothing is
    inferred.
    """
    agentrust = sovp_result.get("agentrust")
    if not isinstance(agentrust, Mapping):
        raise ValueError("SOVP result must contain an 'agentrust' object")

    missing = [field for field in TRACE_REQUIRED_FIELDS if field not in agentrust]
    if missing:
        raise ValueError(f"missing TRACE fields: {', '.join(missing)}")

    sovp = sovp_result.get("sovp", {})
    if not isinstance(sovp, Mapping):
        raise ValueError("'sovp' must be an object when present")

    now = int(time.time())

    return {
        "eat_profile": TRACE_PROFILE_V0_2,
        "iat": now,
        "subject": agentrust["agent_id"],
        "model": {
            "provider": str(agentrust.get("model_provider", "litzki-systems")),
            "model_id": str(agentrust.get("model_id", "sovp")),
            "version": str(agentrust.get("model_version", "0.1.0")),
        },
        "runtime": {
            # No hardware TEE in the bridge; the measurement is transcribed from
            # SOVP and the software-only platform says so.
            "platform": "software-only",
            "measurement": agentrust["tee_measurement"],
            "nonce": sovp.get("nonce"),
        },
        "policy": {
            "bundle_hash": agentrust["policy_hash"],
            "enforcement_mode": _enforcement_mode(agentrust),
        },
        "data_class": agentrust["payload_classification"],
        "origin": {
            # The evidence is asserted by SOVP, not measured here.
            "kind": "third-party-control-plane",
            "producer": "SOVP",
            "source_event_id": str(
                sovp.get("subject", agentrust.get("trace_id", "sovp-attestation"))
            ),
            "ingested_at": now,
        },
        "build_provenance": {
            # slsa_level 0 == no build-provenance guarantee claimed. The catalog
            # hash is the one contextual digest the caller supplies.
            "slsa_level": 0,
            "digest": agentrust["catalog_hash"],
        },
        "appraisal": {
            "status": "none",
            "verifier": "litzki-sovp-agentrust-bridge",
            "timestamp": now,
        },
    }


def sign_trace_record(
    record: Mapping[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    """Return a signed TRACE record.

    Delegates to ``agentrust_trace.sign.sign_record``, which populates ``cnf.jwk``
    with the public key and adds an Ed25519 ``signature`` over the RFC 8785 (JCS)
    canonical form of the record with only the ``signature`` field absent. This is
    the exact convention ``agentrust-trace-tests`` TR-SIG verifies.
    """
    return sign_record(dict(record), private_key)


def trace_signing_pre_image(record: Mapping[str, Any]) -> bytes:
    """Return the canonical signing pre-image for a TRACE record.

    Kept for API stability (re-exported from the package root). Signing itself is
    owned by ``agentrust-trace``; this delegates to the same canonicalization so a
    caller inspecting the pre-image sees exactly the bytes that get signed.
    """
    from agentrust_trace.sign import _canonical_bytes

    return _canonical_bytes({k: v for k, v in record.items() if k != "signature"})
