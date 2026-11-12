"""Device identity (deviceId, key, self-signed certificate) for the KDE Connect link.

The certificate mirrors what kdeconnectd generates for itself (core/sslhelper.cpp):
EC P-256, X.509 v3 without extensions, subject = issuer =
``CN=<deviceId>, O=KDE, OU=KDE Connect``, signed with ECDSA-SHA512. kdeconnectd pins
it at pairing time, so it is created once and never regenerated.
"""

from __future__ import annotations

import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DEVICE_ID_FILE = "device_id"
CERT_FILE = "certificate.pem"
KEY_FILE = "privateKey.pem"


@dataclass(frozen=True)
class DeviceCredentials:
    device_id: str
    cert_pem: bytes
    key_pem: bytes
    cert_path: Path
    key_path: Path


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _build_certificate(device_id: str, now: datetime) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KDE"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "KDE Connect"),
    ])
    serial = secrets.randbits(159) | 1  # positive, < 2^159
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA512())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def certificate_cn(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        raise ValueError("certificate has no CN")
    return str(attrs[0].value)


def public_key_spki_der(cert_pem: bytes) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def certificate_der(cert_pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)


def load_or_create_credentials(directory: Path, *, now: Optional[datetime] = None) -> DeviceCredentials:
    """Load the bridge identity from ``directory`` or create it on first use.

    An incomplete set of files or a certificate whose CN differs from the stored
    device id raises ``ValueError`` instead of silently replacing the identity.
    """
    directory = Path(directory)
    id_path = directory / DEVICE_ID_FILE
    cert_path = directory / CERT_FILE
    key_path = directory / KEY_FILE
    present = [p.exists() for p in (id_path, cert_path, key_path)]

    if all(present):
        device_id = id_path.read_text(encoding="ascii").strip()
        cert_pem = cert_path.read_bytes()
        key_pem = key_path.read_bytes()
        if certificate_cn(cert_pem) != device_id:
            raise ValueError(f"Certificate CN does not match device id in {directory}")
        return DeviceCredentials(device_id, cert_pem, key_pem, cert_path, key_path)
    if any(present):
        raise ValueError(f"Incomplete KDE Connect identity in {directory}; refusing to overwrite it")

    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    device_id = uuid.uuid4().hex
    cert_pem, key_pem = _build_certificate(device_id, now or datetime.now(timezone.utc))
    _write_private(key_path, key_pem)
    _write_private(cert_path, cert_pem)
    _write_private(id_path, device_id.encode("ascii") + b"\n")
    return DeviceCredentials(device_id, cert_pem, key_pem, cert_path, key_path)
