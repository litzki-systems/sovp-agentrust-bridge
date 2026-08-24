import copy

import pytest
from agentrust_trace import verify_record
from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import TRACE_PROFILE_V0_2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trace_tests.result import Status
from trace_tests.runner import run

from litzki_sovp.trace import build_trace_record, sign_trace_record, trace_signing_pre_image


def _sovp_result():
    return {
        "agentrust": {
            "trace_id": "0192f3a0-0000-7000-8000-0000000000aa",
            "agent_id": "spiffe://litzki.systems/agent/sovp-demo",
            "policy_hash": "sha256:" + "a1" * 32,
            "catalog_hash": "sha256:" + "b2" * 32,
            "decision": "allow",
            "decision_reason": "SOVP attestation result accepted by caller policy.",
            "payload_classification": "internal",
            "tee_measurement": "sha256:" + "cd" * 32,
        },
        "sovp": {"result": "passed", "measurement": "sha256:" + "cd" * 32, "nonce": "example-nonce", "subject": "sovp-demo"},
    }


def test_build_trace_record_requires_explicit_trace_fields():
    source = _sovp_result()
    del source["agentrust"]["policy_hash"]

    with pytest.raises(ValueError, match="policy_hash"):
        build_trace_record(source)


def test_build_trace_record_is_a_structurally_valid_v0_2_record():
    record = build_trace_record(_sovp_result())

    assert record["eat_profile"] == TRACE_PROFILE_V0_2
    # The unsigned record is a valid TrustRecord except for the cnf/signature that
    # signing adds, so validate the signed form.
    signed = sign_trace_record(record, Ed25519PrivateKey.generate())
    TrustRecord.model_validate(signed)


def test_enforcement_mode_rejects_non_conformant_override():
    source = _sovp_result()
    source["agentrust"]["policy_enforcement_mode"] = "declared"

    with pytest.raises(ValueError, match="TR-POL-002"):
        build_trace_record(source)


def test_signed_record_verifies_with_agentrust_trace():
    private_key = Ed25519PrivateKey.generate()
    signed = sign_trace_record(build_trace_record(_sovp_result()), private_key)

    # Real verifier: profile, freshness, and Ed25519 signature over the JCS pre-image.
    verify_record(signed, private_key.public_key())


def test_tampered_field_invalidates_signature():
    private_key = Ed25519PrivateKey.generate()
    signed = sign_trace_record(build_trace_record(_sovp_result()), private_key)

    tampered = copy.deepcopy(signed)
    tampered["data_class"] = "public"

    with pytest.raises(InvalidSignature):
        verify_record(tampered, private_key.public_key())


def test_pre_image_excludes_only_signature():
    record = sign_trace_record(build_trace_record(_sovp_result()), Ed25519PrivateKey.generate())
    record["signature"] = "one"
    first = trace_signing_pre_image(record)
    record["signature"] = "two"

    assert trace_signing_pre_image(record) == first


def test_record_passes_trace_tests_level_0():
    signed = sign_trace_record(build_trace_record(_sovp_result()), Ed25519PrivateKey.generate())

    results = run(signed, "trace", level=0)
    failures = [
        finding
        for findings in results.values()
        for finding in findings
        if finding.status is Status.FAIL
    ]

    assert not failures, [f.message for f in failures]
