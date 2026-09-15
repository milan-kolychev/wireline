"""Generate a self-signed certificate for the local TLS lab.

    python tools/make_certs.py --out certs

Produces certs/server.crt and certs/server.key, valid for localhost and 127.0.0.1.
These are throwaway lab credentials: the directory is in .gitignore and nothing here
should ever leave the machine that generated it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_self_signed(out_dir: Path, days: int = 365) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = out_dir / "server.crt"
    key_path = out_dir / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="certs")
    parser.add_argument("--days", type=int, default=365)
    args = parser.parse_args()
    cert, key = make_self_signed(Path(args.out), args.days)
    print(f"wrote {cert}\nwrote {key}")
