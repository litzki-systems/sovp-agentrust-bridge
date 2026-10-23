# Evidence boundary: SOVP under TRACE

This page states what a SOVP attestation proves once this bridge has turned it into an AgenTrust TRACE Trust Record, and where that proof stops. It is for anyone who reads such a record and decides whether to rely on it.

Applies to `litzki-sovp-agentrust-bridge` 0.2.0, tested against `agentrust-trace` 0.10.0 with `agentrust-trace-tests` 0.5.1, and against `agentrust-trace` 0.11.0 with `agentrust-trace-tests` 0.6.2.

## Three layers, three separate claims

Three components touch the evidence. Each one makes its own claim, and each claim needs its own check.

| Layer | Produced by | States | Checked by |
|-------|-------------|--------|------------|
| SOVP attestation | the SOVP deployment that inspected the host | the state of an execution environment before execution, signed under a key the serving party anchors in DNS | a SOVP verifier, against the SOVP specification |
| Transcription | this bridge | the caller's SOVP and AgenTrust fields, mapped into TRACE v0.2 shape, plus an optional pointer to the SOVP document with its digest | nobody; the bridge adds no evidence of its own |
| TRACE record | whoever holds the Ed25519 signing key passed to the bridge | the record content, signed over its RFC 8785 canonical form | any TRACE verifier, for example `trace-tests verify --level 0` |

A passing TRACE check covers the third row. The first row stays with SOVP, and the second row adds no guarantee.

## What a passing TRACE check establishes

`trace-tests verify --record <record> --level 0` passes all Level 0 checks: 8 of 8 with `agentrust-trace-tests` 0.5.1, and 12 passed with 3 skipped (optional fields and a Level 1 requirement) with 0.6.2. That result establishes:

- The record has the structure TRACE v0.2 requires at Level 0.
- The record is fresh: `iat` is at most 24 hours old when the check runs.
- The record is byte for byte the one that was signed. Changing any signed field after signing, the `references` entry included, makes the signature check fail; `test_tampered_field_invalidates_signature` and `test_t5_record_with_references_passes_level_0_and_trusted_key_verification` check this on every CI run.
- The signature matches the public key in `cnf.jwk`, the key the record carries itself.

## Where the proof stops

| Record field or property | What it carries | What a relying party needs from elsewhere |
|--------------------------|-----------------|-------------------------------------------|
| `cnf.jwk` and `signature` | The public key travels inside the record. The bridge signs with any Ed25519 key the caller supplies, and the record then verifies against that same key. | A key you already trust. `trace-tests verify` checks against the embedded key, so a record signed with any fresh key passes Level 0 as well. `agentrust_trace.verify_record(record, trusted_key)` checks against a key you supply and rejects the rest; `test_t7_foreign_key_passes_level_0_but_fails_trusted_key_verification` shows both outcomes on every CI run. Agent Manifest spec §5.3.3 states the same rule for manifests: a key identifier identifies a key, it authorizes nothing. |
| SOVP verdict (`references`) | When the caller passes the SOVP document, exactly one entry: `rel: infrastructure-trust`, `id` the document URL, `resolver: urn:sovp:litzki-systems-llc`, `digest` the SHA-256 of the whole document (see below). The verdict itself, for example `CERTIFIED`, is not copied into the record. Without a document the record has no `references` field. | The SOVP document. Fetch it from `id`, recompute the digest, and compare. A match shows the record points at exactly these bytes. Then verify the document's own signature against the host's DNS anchor and read the verdict there. The entry is a pointer, not evidence (TRACE v0.2 §3.1.2): the record signature attests that the record points there, not that the verdict is true. |
| `runtime.nonce` | The SOVP `nonce` the caller supplies in the `sovp` object, copied unchecked. | Do not use it to join the record to the SOVP document. In the current document format the nonce sits in `integrity_proof`, outside the SOVP signature. The digest is the join. |
| `runtime.measurement` | A digest the caller supplies as `tee_measurement`. The bridge copies it unchecked. | An independent measurement source. `runtime.platform` is `software-only`, so no hardware measured this value. |
| `policy.enforcement_mode` | Derived from the caller's input. A caller `decision` yields `enforce`, its absence yields `advisory`, unless the caller sets the mode explicitly. | Evidence from the enforcing component. The bridge observes no enforcement. |
| `appraisal.status: none` | No verifier has appraised the SOVP result. `appraisal.verifier` names the bridge as transcriber. | An appraisal of your own, before or after the bridge, if your policy requires one. |
| `build_provenance.slsa_level: 0` | No supply chain claim. `digest` carries the caller's `catalog_hash`. | Build provenance from the build system. |
| `origin.kind: third-party-control-plane` | The evidence comes from SOVP, an external system. | Nothing further; the field states the boundary itself. |
| `model.*` | Descriptive defaults (`litzki-systems`, `sovp`, `0.1.0`) unless the caller overrides them. | Treat them as labels. |

Level 0 is the ceiling for this bridge by design. Higher TRACE levels require hardware measurement and independent appraisal, and a transcription step supplies neither. The `references` entry does not change that: TRACE defines the block as assurance neutral.

## How the digest is computed

The bridge hashes the SOVP document exactly as the caller passes it, as a whole, `integrity_proof` included:

```
digest = "sha256:" + hex( SHA-256( RFC 8785 canonical UTF-8 bytes of the whole document ) )
```

Recompute it yourself:

```python
import hashlib, json, rfc8785

doc = json.load(open("sovp-attestation.json", encoding="utf-8"))
print("sha256:" + hashlib.sha256(rfc8785.dumps(doc)).hexdigest())
```

RFC 8785 fixes key order, number form and string escaping, so whitespace and key order in the served file do not matter; any change to a value does. The bridge does not use a `contentAddress` from the document, because the current SovereignAttestation format carries none.

Before it writes the entry, the bridge checks plausibility and rejects the input otherwise: `@type` must be `SovereignAttestation`, the URL must use https, its path must be exactly `/.well-known/sovp-attestation.json` with no query or fragment, and its host must equal `subject.domain` in the document. These checks guard against mistakes. They prove nothing about the document; the bridge fetches nothing and verifies no SOVP signature, because that requires a DNS lookup.

`infrastructure-trust` is not one of the `rel` values TRACE v0.2 registers today. The specification keeps `rel` an open registry, and the schema accepts any value.

## What SOVP evidence covers

A SOVP attestation is infrastructure evidence about the state of an execution environment before execution. It makes no statement about what an agent may do, how it behaves at runtime, or what an Agent Manifest contains. The SOVP Internet-Draft ([draft-litzki-sovp](https://datatracker.ietf.org/doc/draft-litzki-sovp/)) defines the document, its signature and its verification.

The DNS record that anchors the SOVP signing key sits under the control of the party that serves the document. On its own it shows that the document and the key come from one party. Whether that party may attest for the host is a separate authorization question, the same one §5.3.3 answers for Agent Manifest issuers.

The SovereignAttestation document on litzki-systems.com still uses the earlier format: `created` and `nonce` sit in `integrity_proof`, outside the signature, and the document has no `contentAddress`. Moving it to the v2.0 format of draft-litzki-sovp-04 is planned separately from this bridge.

## Relying on SOVP evidence through TRACE

1. Keep your own list of trusted signing keys for the record producer.
2. Verify the record with `agentrust_trace.verify_record(record, trusted_key, expected_nonce=<nonce you expect>)`. This checks the signature against your key, the 24 hour freshness window and the nonce in one call. `trace-tests verify --level 0` remains useful as a conformance check of the record's structure.
3. Fetch the SOVP document from `references[0].id`, recompute the digest as shown above, and compare it with `references[0].digest`.
4. Verify the SOVP document under the SOVP specification and read the verdict there.
5. Treat each layer as its own claim. A valid TRACE record says nothing about the SOVP verdict, and a valid SOVP document says nothing about the agent's runtime behavior.

## Reproduce

The [README](../README.md#conformance) contains the commands. CI runs the test suite, `trace-tests verify --level 0` and a digest recomputation on Python 3.11 and 3.12, against both tested package sets, on every push and pull request. The AgenTrust maintainers reproduced the Level 0 result independently for release 0.1.1 on 2026-09-23 and for release 0.2.0 on 2026-10-12, the second time including an independent recomputation of the `references` digest; see the [Marketplace entry](https://github.com/agentrust-io/integrations/tree/main/integrations/litzki-systems-sovp) and the [review on PR #295](https://github.com/agentrust-io/integrations/pull/295#pullrequestreview-5494622603).
