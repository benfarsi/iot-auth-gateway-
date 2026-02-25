#!/usr/bin/env python3
"""
provision.py — Signed device provisioning workflow.

Generates a device-specific EC key and certificate signed by the CA, then
records the device in the SQLite registry. The provisioning token written to
stdout can be delivered to the device via a secure out-of-band channel (QR code,
NFC tap, hardware HSM programming, etc.).

Usage:
    python3 provisioning/provision.py --device-id sensor-001 --pki-dir pki/ca
    python3 provisioning/provision.py --device-id sensor-002 --revoke
"""

import argparse
import datetime
import json
import os
import secrets
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
except ImportError:
    print("ERROR: pip install cryptography", file=sys.stderr)
    sys.exit(1)

from device_registry import DeviceRegistry


def load_ca(pki_dir: Path):
    """Return (ca_key, ca_cert) loaded from pki_dir."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    ca_key = load_pem_private_key((pki_dir / "ca.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((pki_dir / "ca.crt").read_bytes())
    return ca_key, ca_cert


def issue_device_cert(device_id: str, pki_dir: Path, output_dir: Path) -> dict:
    """
    Issue a client certificate for device_id.
    Returns a provisioning bundle (paths + serial + token).
    """
    ca_key, ca_cert = load_ca(pki_dir)

    dev_key = ec.generate_private_key(ec.SECP256R1())
    key_path = output_dir / f"{device_id}.key"
    cert_path = output_dir / f"{device_id}.crt"

    key_path.write_bytes(
        dev_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IoT Devices"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT Platform"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(dev_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)

    serial_hex = f"{cert.serial_number:X}"
    provisioning_token = secrets.token_urlsafe(32)

    return {
        "device_id": device_id,
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        "serial": serial_hex,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "provisioning_token": provisioning_token,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT device provisioning tool")
    parser.add_argument("--device-id", required=True, help="Unique device identifier (used as cert CN)")
    parser.add_argument("--pki-dir", default="pki/ca", help="Path to CA key/cert directory")
    parser.add_argument("--device-dir", default="pki/devices", help="Output directory for device keys/certs")
    parser.add_argument("--db", default="pki/devices.db", help="SQLite device registry path")
    parser.add_argument("--revoke", action="store_true", help="Revoke the device instead of provisioning")
    args = parser.parse_args()

    pki_dir = Path(args.pki_dir)
    device_dir = Path(args.device_dir)
    device_dir.mkdir(parents=True, exist_ok=True)

    registry = DeviceRegistry(args.db)

    if args.revoke:
        registry.revoke(args.device_id)
        print(json.dumps({"status": "revoked", "device_id": args.device_id}, indent=2))
        return

    if registry.exists(args.device_id):
        print(f"ERROR: device '{args.device_id}' already provisioned. Revoke first.", file=sys.stderr)
        sys.exit(1)

    bundle = issue_device_cert(args.device_id, pki_dir, device_dir)
    registry.register(
        device_id=bundle["device_id"],
        serial=bundle["serial"],
        not_after=bundle["not_after"],
        token_hash=bundle["provisioning_token"],  # store hash in production
    )

    print(json.dumps(bundle, indent=2))
    print("\n[+] Deliver cert + key to device via secure out-of-band channel.", file=sys.stderr)


if __name__ == "__main__":
    main()
