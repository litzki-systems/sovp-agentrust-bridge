"""Command line adapter for SOVP attestation JSON to signed TRACE JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from litzki_sovp.trace import build_trace_record, sign_trace_record


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key must be an Ed25519 PEM key")
    return key


def convert_file(
    input_path: Path,
    private_key_path: Path,
    output_path: Path,
    attestation_path: Path | None = None,
    attestation_url: str | None = None,
) -> None:
    sovp_result = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(sovp_result, dict):
        raise ValueError("input must be a JSON object")
    # Command line values override the matching input fields. Nothing is fetched.
    if attestation_path is not None:
        sovp_result["sovp_attestation_document"] = json.loads(
            attestation_path.read_text(encoding="utf-8")
        )
    if attestation_url is not None:
        sovp_result["sovp_attestation_url"] = attestation_url
    private_key = load_private_key(private_key_path)
    record = build_trace_record(sovp_result)
    signed = sign_trace_record(record, private_key)
    output_path.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert SOVP attestation JSON to a signed AgenTrust TRACE record")
    parser.add_argument("--input", required=True, type=Path, help="SOVP attestation result JSON")
    parser.add_argument("--private-key", required=True, type=Path, help="Ed25519 private key in PEM format")
    parser.add_argument("--output", required=True, type=Path, help="Output TRACE JSON path")
    parser.add_argument(
        "--attestation",
        type=Path,
        help="Full SOVP SovereignAttestation document (JSON file). Adds one references entry "
        "with its SHA-256 over RFC 8785 bytes. Overrides sovp_attestation_document in --input.",
    )
    parser.add_argument(
        "--attestation-url",
        help="URL the document was served from, https://<subject.domain>/.well-known/sovp-attestation.json. "
        "Overrides sovp_attestation_url in --input.",
    )
    args = parser.parse_args()
    try:
        convert_file(args.input, args.private_key, args.output, args.attestation, args.attestation_url)
    except ValueError as exc:
        parser.exit(2, f"litzki-sovp-trace: error: {exc}\n")


if __name__ == "__main__":
    main()
