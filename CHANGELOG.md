# Changelog

## Unreleased

### Documentation
- `integration.yaml` and `docs/evidence-boundary.md` record the maintainers' reproduction of 0.2.0 on 2026-10-12 in a fresh Windows Python 3.12 environment, including an independent recomputation of the `references` digest (review on agentrust-io/integrations PR #295).
- The 0.2.0 heading carries its release date.

## 0.2.0 (2026-10-11)

### Added

- Optional binding to the SOVP verdict document. Pass the full `SovereignAttestation` document as `sovp_attestation_document` with its source `sovp_attestation_url` in the input, or use the new CLI options `--attestation <file>` and `--attestation-url <url>`. The record then carries exactly one `references` entry (TRACE v0.2 §3.1.2): `rel: infrastructure-trust`, `id` the URL, `resolver: urn:sovp:litzki-systems-llc`, and `digest` = `sha256:` + SHA-256 over the RFC 8785 bytes of the whole document, `integrity_proof` included.
- Plausibility checks on that input: `@type` must be `SovereignAttestation`, the URL must use https, its path must be exactly `/.well-known/sovp-attestation.json`, and its host must equal `subject.domain`. Anything else raises `ValueError` (CLI exit code 2).
- Public helpers `sovp_document_digest` and `sovp_reference`.
- `docs/evidence-boundary.md`: what a record proves and where that proof stops, field by field.
- Tests T1 to T7: digest recomputed independently, no `references` without a document, one changed character changes the digest, rejected host/type/path, Level 0 and trusted-key verification with `references`, stable digest for non-ASCII content, and a record signed with a foreign key that passes Level 0 but fails `verify_record(record, trusted_key)`.
- CI runs against the tested versions (`agentrust-trace` 0.10.0, `agentrust-trace-tests` 0.5.1) and the latest PyPI releases, and recomputes the digest of the example record.

### Changed

- `examples/sovp-attestation.json` embeds an unmodified copy of the live SOVP document on litzki-systems.com as served on 2026-10-11.
- `integration.yaml` matches the marketplace listing: `tier: verified`, granted in agentrust-io/integrations PR #220 after the maintainers' reproduction of 0.1.1 on 2026-09-23. A review of 0.2.0 is requested.
- New direct dependency `rfc8785>=0.1.4` (already required by `agentrust-trace`).

### Unchanged

- Without a SOVP document the output is the same as in 0.1.1, with no `references` field.
- The bridge fetches nothing, does not verify the SOVP signature, and does not copy the verdict into the record. `runtime.platform`, `origin.kind`, `appraisal.status` and `build_provenance.slsa_level` keep their weakest honest values. Level 0 remains the ceiling.

## 0.1.1

- TRACE conformance fix: `appraisal.verifier` is a URI.
- Example and test SOVP verdict set to a real value.

## 0.1.0

- First release: SOVP attestation result to signed AgenTrust TRACE v0.2 record, Level 0.
