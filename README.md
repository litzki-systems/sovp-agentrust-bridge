# SOVP → AgenTrust TRACE Bridge

[![conformance](https://github.com/litzki-systems/sovp-agentrust-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/litzki-systems/sovp-agentrust-bridge/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![TRACE conformance: Level 0](https://img.shields.io/badge/TRACE%20conformance-Level%200-success.svg)](#conformance)

Turns a SOVP attestation result into an **Ed25519-signed AgenTrust TRACE Trust
Record** that passes [`agentrust-trace-tests`](https://pypi.org/project/agentrust-trace-tests/)
at Level 0. It maps the caller-supplied fields into a TRACE v0.2 envelope, signs
the record with the released `agentrust-trace` signing implementation, and writes
JSON any TRACE verifier can check.

## What it does

- Loads a SOVP attestation result from JSON.
- Maps the explicitly supplied SOVP and AgenTrust fields into a TRACE v0.2 `TrustRecord`.
- Signs the record with Ed25519 over the RFC 8785 (JCS) canonical pre-image, binding the public key into `cnf.jwk` — exactly what `agentrust-trace-tests` `TR-SIG` verifies.
- Optionally points the record at the SOVP verdict document: given the full
  `SovereignAttestation` document, it adds one `references` entry whose `digest`
  binds exactly that document (see [Binding to the SOVP verdict](#binding-to-the-sovp-verdict)).
- Writes the signed record as JSON for downstream validation.

What a record proves, and where that proof stops, is set out field by field in
[docs/evidence-boundary.md](docs/evidence-boundary.md).

## What it does not claim

The bridge *transcribes* a SOVP attestation; it does not measure a hardware TEE.
Every field that would assert a strong guarantee is set to its weakest honest
value — `runtime.platform: software-only`, `origin.kind: third-party-control-plane`,
`appraisal.status: none`, `build_provenance.slsa_level: 0`. It does not certify
SOVP, does not call non-attested data attested, and infers no attestation claim
it was not given. It does not verify the SOVP document's signature (that needs a
DNS lookup) and does not copy the SOVP verdict into the record.

## Install

```bash
pip install litzki-sovp-agentrust-bridge
```

## Usage

```bash
# Throwaway local signing key (git-ignored; never commit it):
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem

# Emit a signed TRACE record from the example SOVP attestation. The example
# input embeds a copy of the live SOVP document, so the record gets a
# references entry:
litzki-sovp-trace \
  --input integrations/litzki-sovp/examples/sovp-attestation.json \
  --private-key ed25519-private.pem \
  --output sovp.trace.json

# Or pass the SOVP document as its own file. --attestation and
# --attestation-url override the matching fields in --input:
curl -sSo sovp-attestation-doc.json https://litzki-systems.com/.well-known/sovp-attestation.json
litzki-sovp-trace \
  --input integrations/litzki-sovp/examples/sovp-attestation.json \
  --attestation sovp-attestation-doc.json \
  --attestation-url https://litzki-systems.com/.well-known/sovp-attestation.json \
  --private-key ed25519-private.pem \
  --output sovp.trace.json
```

TRACE records are fresh for 24 hours after `iat`. Generate a new record for
every check rather than reusing an old one.

## Binding to the SOVP verdict

With a SOVP document, the record carries exactly one entry:

```json
"references": [{
  "rel": "infrastructure-trust",
  "id": "https://litzki-systems.com/.well-known/sovp-attestation.json",
  "resolver": "urn:sovp:litzki-systems-llc",
  "digest": "sha256:<hex>"
}]
```

The digest is SHA-256 over the RFC 8785 (JCS) canonical bytes of the **whole**
document as passed in, `integrity_proof` included. Recompute it:

```python
import hashlib, json, rfc8785

doc = json.load(open("sovp-attestation-doc.json", encoding="utf-8"))
print("sha256:" + hashlib.sha256(rfc8785.dumps(doc)).hexdigest())
```

The bridge rejects the input with `ValueError` (CLI exit code 2) unless `@type`
is `SovereignAttestation`, the URL uses https, its path is exactly
`/.well-known/sovp-attestation.json`, and its host equals `subject.domain` in the
document. It fetches nothing. Without a document there is no `references` field,
exactly as in 0.1.x.

The entry is a pointer, not evidence (TRACE v0.2 §3.1.2). It changes no
assurance field, and Level 0 stays the ceiling.

## Conformance

```bash
python -m pytest integrations/litzki-sovp/tests
trace-tests verify --record sovp.trace.json --level 0
# agentrust-trace-tests 0.5.1: Result: PASS (8 checks, 0 skipped)
# agentrust-trace-tests 0.6.2: Result: PASS (15 checks, 3 skipped)
```

Records pass TRACE conformance at **Level 0**. Unlike an unsigned-artifact Level 0,
`TR-SIG` reports `Ed25519 signature verified`. Level 0 is the honest ceiling for a
`software-only` transcription bridge; the suite accepts that platform only at
Level 0. CI runs this reproduction on every push and pull request across Python
3.11 and 3.12, against the pinned tested versions and the latest PyPI releases.

`trace-tests verify` checks the signature against the key the record carries in
`cnf.jwk`. A record signed with **any** key passes it. To rely on a record, verify
it against a key you already trust:

```python
import json
from agentrust_trace import verify_record
from cryptography.hazmat.primitives import serialization

record = json.load(open("sovp.trace.json", encoding="utf-8"))
trusted_key = serialization.load_pem_public_key(open("ed25519-public.pem", "rb").read())

# Raises unless the record is signed by trusted_key, is at most 24 hours old,
# and carries the nonce you expect.
verify_record(record, trusted_key, expected_nonce="example-nonce")  # the example input's nonce
```

A record signed with a different key fails this call, even though it passes
Level 0; `test_t7_foreign_key_passes_level_0_but_fails_trusted_key_verification`
checks both outcomes on every CI run.

## Marketplace

The integration and its manifest live in
[`integrations/litzki-sovp/`](integrations/litzki-sovp/). See its
[README](integrations/litzki-sovp/README.md) and
[`integration.yaml`](integrations/litzki-sovp/integration.yaml) for the
[AgenTrust Marketplace](https://agentrust-io.com/marketplace/) listing.

## License

Apache-2.0 — see [LICENSE](LICENSE).
