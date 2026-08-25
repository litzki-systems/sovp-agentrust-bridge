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
- Writes the signed record as JSON for downstream validation.

## What it does not claim

The bridge *transcribes* a SOVP attestation; it does not measure a hardware TEE.
Every field that would assert a strong guarantee is set to its weakest honest
value — `runtime.platform: software-only`, `origin.kind: third-party-control-plane`,
`appraisal.status: none`, `build_provenance.slsa_level: 0`. It does not certify
SOVP, does not call non-attested data attested, and infers no attestation claim
it was not given.

## Install

```bash
pip install litzki-sovp-agentrust-bridge
```

## Usage

```bash
# Throwaway local signing key (git-ignored; never commit it):
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem

# Emit a signed TRACE record from the example SOVP attestation:
litzki-sovp-trace \
  --input integrations/litzki-sovp/examples/sovp-attestation.json \
  --private-key ed25519-private.pem \
  --output sovp.trace.json
```

## Conformance

```bash
python -m pytest integrations/litzki-sovp/tests
trace-tests verify --record sovp.trace.json --level 0
# Result: PASS (8 checks, 0 failures) — TR-ENV, TR-SIG, TR-POL
```

Records pass TRACE conformance at **Level 0**. Unlike an unsigned-artifact Level 0,
`TR-SIG` reports `Ed25519 signature verified` — the record carries a real signature
re-verifiable with `agentrust_trace.verify_record(record, public_key)`. Level 0 is
the honest ceiling for a `software-only` transcription bridge; the suite accepts
that platform only at Level 0. CI runs this reproduction on every push and pull
request across Python 3.11 and 3.12.

## Marketplace

The integration and its manifest live in
[`integrations/litzki-sovp/`](integrations/litzki-sovp/). See its
[README](integrations/litzki-sovp/README.md) and
[`integration.yaml`](integrations/litzki-sovp/integration.yaml) for the
[AgenTrust Marketplace](https://agentrust-io.com/marketplace/) listing.

## License

Apache-2.0 — see [LICENSE](LICENSE).
