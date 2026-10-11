import copy
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from agentrust_trace import verify_record
from agentrust_trace.models import TrustRecord
from agentrust_trace.sign import TRACE_PROFILE_V0_2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from trace_tests.result import Status
from trace_tests.runner import run

from litzki_sovp.trace import (
    build_trace_record,
    sign_trace_record,
    sovp_document_digest,
    trace_signing_pre_image,
)


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
        "sovp": {"result": "CERTIFIED", "measurement": "sha256:" + "cd" * 32, "nonce": "example-nonce", "subject": "sovp-demo"},
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


def test_appraisal_verifier_is_a_uri_and_record_passes_full_schema():
    # agentrust-trace >= 0.10.0 enforces the full TRACE v0.2 JSON Schema inside
    # verify_record, including `format: uri` on appraisal.verifier. A bare package
    # name is not a URI, so the record must carry a URI here to stay verifiable.
    from agentrust_trace.validate import iter_errors

    signed = sign_trace_record(build_trace_record(_sovp_result()), Ed25519PrivateKey.generate())

    assert signed["appraisal"]["verifier"] == "https://github.com/litzki-systems/sovp-agentrust-bridge"
    assert iter_errors(signed) == []


def test_non_ascii_fields_round_trip_through_canonical_signing():
    # The bridge signs over the RFC 8785 (JCS) canonical form. Guards the upstream
    # RFC 8785 conformance fixes the signing layer relies on: JSON strings are not
    # NFC-normalized (so umlauts are preserved byte-for-byte, no signature collision)
    # and only the ECMAScript-standard escape set is applied (so non-ASCII code
    # points are emitted as raw UTF-8, not \uXXXX escapes).
    private_key = Ed25519PrivateKey.generate()
    source = _sovp_result()
    source["sovp"]["subject"] = "Grüße-Ünïçōdé-über"

    signed = sign_trace_record(build_trace_record(source), private_key)

    # Non-ASCII survives transcription unchanged and the record still verifies.
    assert signed["origin"]["source_event_id"] == "Grüße-Ünïçōdé-über"
    verify_record(signed, private_key.public_key())

    pre_image = trace_signing_pre_image(signed)
    assert "ü".encode("utf-8") in pre_image  # raw UTF-8, not NFC-folded away
    assert b"\\u00fc" not in pre_image  # and not escaped to ASCII


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


# --- 0.2.0: references entry pointing at the SOVP verdict document -------------

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
_URL = "https://litzki-systems.com/.well-known/sovp-attestation.json"


def _attestation_document():
    # Same shape as the live SovereignAttestation document on litzki-systems.com.
    return {
        "@context": "https://litzki-systems.com/protocol/sovp-attestation-v1",
        "@type": "SovereignAttestation",
        "subject": {"domain": "litzki-systems.com", "canonical_url": "https://litzki-systems.com"},
        "attestation": {
            "verdict": "CERTIFIED",
            "sovereignScore": 100,
            "scanned_at": "2026-09-08T23:17:55.646Z",
            "valid_until": "2026-12-07T23:17:55.646Z",
        },
        "issuer": {"uid": "urn:sovp:litzki-systems-llc", "canonical_url": "https://litzki-systems.com"},
        "integrity_proof": {
            "signature": "c2lnbmF0dXJl",
            "created": "2026-09-08T23:18:36.780Z",
            "public_key_ref": "dns:txt:_sovp-attestation.litzki-systems.com",
            "nonce": "c103e9ac-fc63-4c4d-8e28-0963a963e1af",
        },
    }


def _with_document(document=None, url=_URL):
    source = _sovp_result()
    source["sovp_attestation_document"] = _attestation_document() if document is None else document
    source["sovp_attestation_url"] = url
    return source


def _independent_digest(document):
    # Recomputed here without the bridge: SHA-256 over the RFC 8785 bytes of the
    # whole document, integrity_proof included.
    return "sha256:" + hashlib.sha256(rfc8785.dumps(document)).hexdigest()


def test_t1_document_yields_exactly_one_reference_with_correct_digest():
    document = _attestation_document()
    record = build_trace_record(_with_document(document))

    assert record["references"] == [
        {
            "rel": "infrastructure-trust",
            "id": _URL,
            "resolver": "urn:sovp:litzki-systems-llc",
            "digest": _independent_digest(document),
        }
    ]
    # No new claims: assurance fields stay at their weakest honest values and the
    # verdict is not copied into the record.
    assert record["runtime"]["platform"] == "software-only"
    assert record["origin"]["kind"] == "third-party-control-plane"
    assert record["appraisal"]["status"] == "none"
    assert record["build_provenance"]["slsa_level"] == 0
    assert "CERTIFIED" not in json.dumps(record)


def test_t2_without_document_there_is_no_references_field():
    record = build_trace_record(_sovp_result())
    assert "references" not in record

    # A URL alone adds nothing either: the reference needs the document.
    source = _sovp_result()
    source["sovp_attestation_url"] = _URL
    assert "references" not in build_trace_record(source)


def test_t3_one_changed_character_changes_the_digest():
    document = _attestation_document()
    changed = copy.deepcopy(document)
    changed["attestation"]["verdict"] = "CERTIFIEd"
    in_proof = copy.deepcopy(document)
    in_proof["integrity_proof"]["nonce"] = in_proof["integrity_proof"]["nonce"][:-1] + "0"

    digest = sovp_document_digest(document)
    assert sovp_document_digest(changed) != digest
    # integrity_proof is inside the hashed bytes as well.
    assert sovp_document_digest(in_proof) != digest
    # Key order and whitespace are not part of the canonical bytes.
    reordered = json.loads(json.dumps(document, indent=4, sort_keys=True))
    assert sovp_document_digest(reordered) == digest


@pytest.mark.parametrize(
    ("mutate", "url", "match"),
    [
        (lambda d: d, "https://evil.example/.well-known/sovp-attestation.json", "does not match subject.domain"),
        (lambda d: d, "https://sub.litzki-systems.com/.well-known/sovp-attestation.json", "does not match subject.domain"),
        (lambda d: d, "https://litzki-systems.com:8443/.well-known/sovp-attestation.json", "does not match subject.domain"),
        (lambda d: d.update({"@type": "SovereignIdentity"}), _URL, "@type"),
        (lambda d: d.pop("@type"), _URL, "@type"),
        (lambda d: d, "https://litzki-systems.com/.well-known/sovp-identity.json", "/.well-known/sovp-attestation.json"),
        (lambda d: d, "https://litzki-systems.com/x/.well-known/sovp-attestation.json", "/.well-known/sovp-attestation.json"),
        (lambda d: d, "https://litzki-systems.com/.well-known/sovp-attestation.json?v=1", "/.well-known/sovp-attestation.json"),
        (lambda d: d, "http://litzki-systems.com/.well-known/sovp-attestation.json", "https"),
        (lambda d: d, None, "sovp_attestation_url is required"),
        (lambda d: d.pop("subject"), _URL, "subject.domain"),
    ],
)
def test_t4_implausible_document_or_url_is_rejected(mutate, url, match):
    document = _attestation_document()
    mutate(document)

    with pytest.raises(ValueError, match=match):
        build_trace_record(_with_document(document, url))


def test_t4_url_host_comparison_ignores_case():
    record = build_trace_record(
        _with_document(url="https://Litzki-Systems.com/.well-known/sovp-attestation.json")
    )
    assert len(record["references"]) == 1


def test_t5_record_with_references_passes_level_0_and_trusted_key_verification():
    from agentrust_trace.validate import iter_errors

    private_key = Ed25519PrivateKey.generate()
    signed = sign_trace_record(build_trace_record(_with_document()), private_key)

    assert iter_errors(signed) == []
    TrustRecord.model_validate(signed)
    verify_record(signed, private_key.public_key(), expected_nonce="example-nonce")

    results = run(signed, "trace", level=0)
    findings = [finding for group in results.values() for finding in group]
    assert not [f.message for f in findings if f.status is Status.FAIL]
    # 0.5.x runs 8 checks at Level 0; 0.6.x runs 12 and skips 3 optional or
    # Level 1 ones. None may fail, and the signature check must have passed.
    assert any(f.status is Status.PASS and f.message == "Ed25519 signature verified" for f in findings)

    # The reference is inside the signature: changing it breaks verification.
    tampered = copy.deepcopy(signed)
    tampered["references"][0]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(InvalidSignature):
        verify_record(tampered, private_key.public_key())


def test_t6_non_ascii_document_digest_is_stable():
    document = _attestation_document()
    document["subject"]["note"] = "Grüße aus Chiapas, señor, über 100 %   \U0001F600"
    expected = _independent_digest(document)

    assert sovp_document_digest(document) == expected
    # Stable across a JSON round trip, with or without ASCII escaping.
    for text in (json.dumps(document), json.dumps(document, ensure_ascii=False, indent=2)):
        assert sovp_document_digest(json.loads(text)) == expected
    # Raw UTF-8 in the hashed bytes, not \\u escapes.
    assert "ü".encode("utf-8") in rfc8785.dumps(document)

    private_key = Ed25519PrivateKey.generate()
    signed = sign_trace_record(build_trace_record(_with_document(document)), private_key)
    assert signed["references"][0]["digest"] == expected
    verify_record(signed, private_key.public_key())


def test_t7_foreign_key_passes_level_0_but_fails_trusted_key_verification():
    # Finding 1: the record carries its own key in cnf.jwk, and the Level 0 suite
    # checks against that embedded key. A record signed by anyone passes it.
    # Only verify_record with a key the relying party already trusts tells them apart.
    trusted_key = Ed25519PrivateKey.generate()
    foreign_key = Ed25519PrivateKey.generate()
    forged = sign_trace_record(build_trace_record(_with_document()), foreign_key)

    results = run(forged, "trace", level=0)
    assert not [f for group in results.values() for f in group if f.status is Status.FAIL]

    # Rejected before the signature is even checked: cnf.jwk does not name the
    # trusted key.
    with pytest.raises(ValueError, match="does not identify the trusted key"):
        verify_record(forged, trusted_key.public_key())

    # Same verdict when the forger copies the trusted public key into cnf.jwk
    # without holding its private key: now the signature itself fails.
    from agentrust_trace.sign import key_to_jwk

    spoofed = copy.deepcopy(forged)
    spoofed["cnf"]["jwk"] = key_to_jwk(trusted_key)  # public part only
    with pytest.raises(InvalidSignature):
        verify_record(spoofed, trusted_key.public_key())


def test_example_input_carries_the_live_document_copy():
    source = json.loads((_EXAMPLES / "sovp-attestation.json").read_text(encoding="utf-8"))
    document = source["sovp_attestation_document"]

    assert document["@type"] == "SovereignAttestation"
    assert document["attestation"]["verdict"] == source["sovp"]["result"]
    record = build_trace_record(source)
    assert record["references"][0]["digest"] == _independent_digest(document)
