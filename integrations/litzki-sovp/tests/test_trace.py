import base64
import copy

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from litzki_sovp.trace import build_trace_record, sign_trace_record, trace_signing_pre_image


def _sovp_result():
    return {
        "agentrust": {
            "trace_id": "0192f3a0-0000-7000-8000-0000000000aa",
            "agent_id": "spiffe://litzki.systems/agent/sovp-demo",
            "agent_manifest_id": "0192f3a0-0000-7000-8000-000000000001",
            "manifest_verification_result": "VALID",
            "tool_id": "systems.litzki.sovp.attestation",
            "policy_hash": "sha256:" + "a1" * 32,
            "catalog_hash": "sha256:" + "b2" * 32,
            "decision": "allow",
            "decision_reason": "SOVP attestation result accepted by caller policy.",
            "payload_classification": "internal",
            "egress_destination": "trace.local",
            "hitl_required": False,
            "hitl_approval_id": None,
            "timestamp": "2026-08-22T00:00:00Z",
            "tee_measurement": "sha256:" + "cd" * 32,
        },
        "sovp": {"result": "passed", "measurement": "sha256:" + "cd" * 32},
    }


def test_build_trace_record_requires_explicit_trace_fields():
    source = _sovp_result()
    del source["agentrust"]["policy_hash"]

    try:
        build_trace_record(source)
    except ValueError as exc:
        assert "policy_hash" in str(exc)
    else:
        raise AssertionError("missing policy_hash should fail")


def test_trace_pre_image_excludes_only_signature():
    record = build_trace_record(_sovp_result())
    record["signature"] = "one"
    first = trace_signing_pre_image(record)
    record["signature"] = "two"

    assert trace_signing_pre_image(record) == first


def test_sign_trace_record_binds_covered_fields():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signed = sign_trace_record(build_trace_record(_sovp_result()), private_key)

    public_key.verify(
        base64.urlsafe_b64decode(signed["signature"] + "=="),
        trace_signing_pre_image(signed),
    )

    tampered = copy.deepcopy(signed)
    tampered["decision"] = "deny"

    try:
        public_key.verify(
            base64.urlsafe_b64decode(tampered["signature"] + "=="),
            trace_signing_pre_image(tampered),
        )
    except InvalidSignature:
        pass
    else:
        raise AssertionError("tampered TRACE field should invalidate signature")
