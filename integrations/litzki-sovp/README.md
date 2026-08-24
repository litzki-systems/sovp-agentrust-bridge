# Litzki SOVP AgenTrust Integration

Exports SOVP attestation results as signed AgenTrust TRACE records.

## What it does

This integration provides a Python adapter that:

- loads a SOVP attestation result from JSON;
- maps explicitly supplied SOVP and AgenTrust fields into a TRACE envelope;
- signs the TRACE envelope with Ed25519 over a canonical JSON pre-image that excludes only the `signature` field;
- writes the signed record as JSON for downstream validation with `agentrust-trace-tests`.

## What it does not claim

- It does not certify SOVP or any SOVP deployment.
- It does not call non-attested data attested.
- It does not mark the integration as Verified until the generated records pass `agentrust-trace-tests` in CI or a reviewer reproduction environment.

## Installation

```bash
python -m pip install -e integrations/litzki-sovp
```

The package declares runtime dependencies on released PyPI packages: `cmcp-runtime`, `agentrust-trace`, `agentrust-trace-tests`, and `agent-manifest`.

## Input contract

The adapter expects a JSON object with an `agentrust` object containing the TRACE envelope fields and a `sovp` object containing the source attestation payload. The adapter only signs fields present in `agentrust`; it does not infer missing attestation claims.

See `examples/sovp-attestation.json` for the minimal local fixture shape.

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

The generated record passes TRACE conformance at **Level 0** (`TR-ENV`, `TR-SIG`,
`TR-POL`). Level 0 is the honest ceiling for this bridge: it transcribes a SOVP
attestation rather than measuring a hardware TEE, so `runtime.platform` is
`software-only`, which the suite accepts only at Level 0.
