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

Since 0.2.0 the record can point at the SOVP verdict document. When the caller
supplies the full SovereignAttestation document and the URL it was served from,
the bridge adds exactly one ``references`` entry (TRACE v0.2 section 3.1.2)
whose ``digest`` binds that exact document. The entry is a pointer, not
evidence: the bridge does not verify the SOVP signature (that needs DNS) and the
verdict is not copied into the record as a field of its own.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import rfc8785
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

# ``appraisal.verifier`` must be a URI under the TRACE v0.2 schema. This identifies
# the bridge that transcribed the SOVP evidence into TRACE shape; appraisal.status is
# ``none``, so it names the transcriber, not an appraising verifier.
VERIFIER_URI = "https://github.com/litzki-systems/sovp-agentrust-bridge"

# The ``references`` entry that points at the SOVP verdict document.
SOVP_REFERENCE_REL = "infrastructure-trust"
SOVP_REFERENCE_RESOLVER = "urn:sovp:litzki-systems-llc"
SOVP_ATTESTATION_TYPE = "SovereignAttestation"
SOVP_ATTESTATION_PATH = "/.well-known/sovp-attestation.json"


def sovp_document_digest(document: Mapping[str, Any]) -> str:
    """Return ``sha256:<hex>`` over the RFC 8785 (JCS) bytes of the whole document.

    The whole document is hashed as supplied, including ``integrity_proof``.
    Anyone can recompute it::

        import hashlib, json, rfc8785
        doc = json.load(open("sovp-attestation.json", encoding="utf-8"))
        "sha256:" + hashlib.sha256(rfc8785.dumps(doc)).hexdigest()
    """
    if not isinstance(document, Mapping):
        raise ValueError("sovp_attestation_document must be a JSON object")
    return "sha256:" + hashlib.sha256(rfc8785.dumps(dict(document))).hexdigest()


def sovp_reference(document: Mapping[str, Any], url: Any) -> dict[str, str]:
    """Build the ``references`` entry for a SOVP verdict document.

    Plausibility checks only; nothing is fetched and the SOVP signature is not
    verified. Raises ``ValueError`` when the document is not a
    ``SovereignAttestation``, when ``url`` is not an https URL whose path is
    exactly ``/.well-known/sovp-attestation.json``, or when the URL host differs
    from ``subject.domain`` in the document.
    """
    if not isinstance(document, Mapping):
        raise ValueError("sovp_attestation_document must be a JSON object")
    if document.get("@type") != SOVP_ATTESTATION_TYPE:
        raise ValueError(
            f"sovp_attestation_document @type must be {SOVP_ATTESTATION_TYPE!r}, "
            f"got {document.get('@type')!r}"
        )
    if not isinstance(url, str) or not url:
        raise ValueError("sovp_attestation_url is required when sovp_attestation_document is given")

    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError(f"sovp_attestation_url must use https, got {url!r}")
    if parts.path != SOVP_ATTESTATION_PATH or parts.query or parts.fragment:
        raise ValueError(
            f"sovp_attestation_url must point at {SOVP_ATTESTATION_PATH} with no query or "
            f"fragment, got {url!r}"
        )

    subject = document.get("subject")
    domain = subject.get("domain") if isinstance(subject, Mapping) else None
    if not isinstance(domain, str) or not domain:
        raise ValueError("sovp_attestation_document has no subject.domain")
    if parts.port is not None or (parts.hostname or "") != domain.lower().rstrip("."):
        raise ValueError(
            f"sovp_attestation_url host {parts.netloc!r} does not match subject.domain {domain!r}"
        )

    return {
        "rel": SOVP_REFERENCE_REL,
        "id": url,
        "resolver": SOVP_REFERENCE_RESOLVER,
        "digest": sovp_document_digest(document),
    }


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

    Optionally ``sovp_result`` carries ``sovp_attestation_document`` (the full
    SovereignAttestation JSON object) and ``sovp_attestation_url`` (where it was
    served). With a document the record gets exactly one ``references`` entry,
    see :func:`sovp_reference`; without one the record has no ``references``
    field, exactly as in 0.1.x.
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

    document = sovp_result.get("sovp_attestation_document")
    reference = (
        sovp_reference(document, sovp_result.get("sovp_attestation_url"))
        if document is not None
        else None
    )

    now = int(time.time())

    record: dict[str, Any] = {
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
            # TRACE v0.2 requires ``appraisal.verifier`` to be a URI (the schema
            # verify_record enforces since agentrust-trace 0.10.0). A bare package
            # name is not one, so identify the bridge by its repository URI.
            "verifier": VERIFIER_URI,
            "timestamp": now,
        },
    }
    if reference is not None:
        # A pointer, not evidence (TRACE v0.2 section 3.1.2). It changes no
        # assurance field above; the digest binds the exact verdict document.
        record["references"] = [reference]
    return record


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
