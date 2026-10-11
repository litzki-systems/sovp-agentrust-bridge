# Litzki SOVP AgenTrust Integration

Exports SOVP attestation results as signed AgenTrust TRACE records.

## What it does

This integration provides a Python adapter that:

- loads a SOVP attestation result from JSON;
- maps explicitly supplied SOVP and AgenTrust fields into a TRACE envelope;
- signs the TRACE envelope with Ed25519 over a canonical JSON pre-image that excludes only the `signature` field;
- optionally adds one `references` entry that binds the record by SHA-256 digest to the full SOVP `SovereignAttestation` document;
- writes the signed record as JSON for downstream validation with `agentrust-trace-tests`.

The field-by-field evidence boundary is in [`docs/evidence-boundary.md`](../../docs/evidence-boundary.md).

## What it does not claim

- It does not certify SOVP or any SOVP deployment.
- It does not call non-attested data attested.
- It does not verify the SOVP document's signature and does not copy the SOVP verdict into the record.
- It does not self-declare the Verified tier; the AgenTrust maintainers grant it in marketplace review.

## Installation

```bash
python -m pip install -e integrations/litzki-sovp
```

The package declares runtime dependencies on released PyPI packages: `cmcp-runtime`, `agentrust-trace`, `agentrust-trace-tests`, `agent-manifest`, and `rfc8785`.

## Input contract

The adapter expects a JSON object with an `agentrust` object containing the TRACE envelope fields and a `sovp` object containing the source attestation payload. The adapter only signs fields present in `agentrust`; it does not infer missing attestation claims.

Optional since 0.2.0, at the top level of the input:

- `sovp_attestation_document`: the full SOVP `SovereignAttestation` document as a JSON object;
- `sovp_attestation_url`: the URL it was served from, `https://<subject.domain>/.well-known/sovp-attestation.json`.

With both, the record gets one `references` entry (`rel: infrastructure-trust`, `resolver: urn:sovp:litzki-systems-llc`, `digest` = `sha256:` + SHA-256 over the RFC 8785 bytes of the whole document). A wrong `@type`, a URL host other than `subject.domain` or a path other than `/.well-known/sovp-attestation.json` raises `ValueError`. The CLI options `--attestation <file>` and `--attestation-url <url>` override these fields.

See `examples/sovp-attestation.json` for the fixture shape. Its `sovp_attestation_document` is an unmodified copy of the live document on litzki-systems.com as served on 2026-10-11.

## Usage

First generate a local Ed25519 signing key. This is a throwaway demo key; it is
git-ignored and must not be committed. Use a persistent, protected key for any
record you intend to be re-verified later.

```bash
openssl genpkey -algorithm Ed25519 \
  -out integrations/litzki-sovp/examples/ed25519-private.pem
```

Then produce a signed TRACE record:

```bash
litzki-sovp-trace \
  --input integrations/litzki-sovp/examples/sovp-attestation.json \
  --private-key integrations/litzki-sovp/examples/ed25519-private.pem \
  --output /tmp/sovp.trace.json
```

## Reproduction target

```bash
python -m pytest integrations/litzki-sovp/tests
trace-tests verify --record /tmp/sovp.trace.json --level 0
```

The generated record passes TRACE conformance at **Level 0**. Level 0 is the honest ceiling for this bridge: it transcribes a SOVP
attestation rather than measuring a hardware TEE, so `runtime.platform` is
`software-only`, which the suite accepts only at Level 0.

`trace-tests verify` checks against the key embedded in `cnf.jwk`, so any key passes it. Relying parties verify with `agentrust_trace.verify_record(record, trusted_key, expected_nonce=...)`, which rejects keys they do not already trust. Records are fresh for 24 hours after `iat`.
