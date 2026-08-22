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


def convert_file(input_path: Path, private_key_path: Path, output_path: Path) -> None:
    sovp_result = json.loads(input_path.read_text(encoding="utf-8"))
    private_key = load_private_key(private_key_path)
    record = build_trace_record(sovp_result)
    signed = sign_trace_record(record, private_key)
    output_path.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert SOVP attestation JSON to a signed AgenTrust TRACE record")
    parser.add_argument("--input", required=True, type=Path, help="SOVP attestation result JSON")
    parser.add_argument("--private-key", required=True, type=Path, help="Ed25519 private key in PEM format")
    parser.add_argument("--output", required=True, type=Path, help="Output TRACE JSON path")
    args = parser.parse_args()
    convert_file(args.input, args.private_key, args.output)


if __name__ == "__main__":
    main()
