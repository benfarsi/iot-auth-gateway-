#!/usr/bin/env python3
"""
ca_setup.py — Bootstrap the PKI for the IoT Auth Gateway.

Creates:
  pki/ca/ca.key       — CA private key (RSA 4096, never leaves the PKI host)
  pki/ca/ca.crt       — Self-signed CA certificate (10-year validity)
  pki/ca/server.key   — Gateway server private key (EC P-256)
  pki/ca/server.crt   — Server certificate signed by CA (1-year validity)

Usage:
    python3 provisioning/ca_setup.py --pki-dir pki --cn "IoT Gateway CA"
"""

import argparse
import datetime
import ipaddress
import os
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
except ImportError:
    print("ERROR: Install cryptography: pip install cryptography", file=sys.stderr)
    sys.exit(1)


def _save_key(key, path: Path, password: bytes | None = None) -> None:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, enc)
    )
    os.chmod(path, 0o600)
    print(f"  [+] Key written: {path}")


def _save_cert(cert, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(path, 0o644)
    print(f"  [+] Cert written: {path}")


def create_ca(pki_dir: Path, cn: str, org: str) -> tuple:
    """Generate the root CA key and self-signed certificate."""
    print("\n[*] Generating CA key (RSA-4096) ...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    _save_key(ca_key, pki_dir / "ca.key")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _save_cert(ca_cert, pki_dir / "ca.crt")
    return ca_key, ca_cert


def create_server_cert(pki_dir: Path, ca_key, ca_cert, cn: str, san_ips: list[str], san_dns: list[str]) -> None:
    """Generate the gateway server key and certificate signed by the CA."""
    print("\n[*] Generating server key (EC P-256) ...")
    server_key = ec.generate_private_key(ec.SECP256R1())
    _save_key(server_key, pki_dir / "server.key")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Gateway"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)

    san_entries = [x509.DNSName(d) for d in san_dns]
    for ip in san_ips:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    _save_cert(server_cert, pki_dir / "server.crt")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap IoT Gateway PKI")
    parser.add_argument("--pki-dir", default="pki/ca", help="Directory to write PKI artifacts")
    parser.add_argument("--cn", default="IoT Gateway CA", help="CA Common Name")
    parser.add_argument("--org", default="IoT Platform", help="Organisation name")
    parser.add_argument("--server-cn", default="iot-gateway", help="Server certificate CN")
    parser.add_argument("--san-dns", nargs="*", default=["localhost"], help="SAN DNS names")
    parser.add_argument("--san-ip", nargs="*", default=["127.0.0.1"], help="SAN IP addresses")
    args = parser.parse_args()

    pki_dir = Path(args.pki_dir)
    pki_dir.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = create_ca(pki_dir, args.cn, args.org)
    create_server_cert(pki_dir, ca_key, ca_cert, args.server_cn, args.san_ip, args.san_dns)

    print("\n[+] PKI bootstrap complete.")
    print(f"    CA cert  : {pki_dir}/ca.crt")
    print(f"    Server   : {pki_dir}/server.crt + server.key")
    print("\n    Next: python3 provisioning/provision.py --device-id <id>")


if __name__ == "__main__":
    main()
