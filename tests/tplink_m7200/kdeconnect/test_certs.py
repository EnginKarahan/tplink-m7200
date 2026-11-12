import os
import stat
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tplink_m7200.kdeconnect.certs import (
    certificate_cn,
    load_or_create_credentials,
    public_key_spki_der,
)
from tplink_m7200.kdeconnect.packets import is_valid_device_id


def test_create_matches_kdeconnect_shape(tmp_path):
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    creds = load_or_create_credentials(tmp_path / "kc", now=now)
    assert is_valid_device_id(creds.device_id) and len(creds.device_id) == 32
    cert = x509.load_pem_x509_certificate(creds.cert_pem)
    assert cert.version == x509.Version.v3
    assert len(cert.extensions) == 0
    assert cert.subject == cert.issuer
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == creds.device_id
    assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "KDE"
    assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "KDE Connect"
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == "secp256r1"
    assert cert.signature_hash_algorithm.name == "sha512"
    assert cert.not_valid_before_utc == now - timedelta(days=365)
    assert cert.not_valid_after_utc == now + timedelta(days=3650)
    assert 0 < cert.serial_number < 2 ** 159
    for path in (creds.cert_path, creds.key_path, tmp_path / "kc" / "device_id"):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "kc").st_mode) == 0o700


def test_reload_is_stable(tmp_path):
    first = load_or_create_credentials(tmp_path / "kc")
    second = load_or_create_credentials(tmp_path / "kc")
    assert first == second
    assert certificate_cn(second.cert_pem) == first.device_id
    assert public_key_spki_der(first.cert_pem).startswith(b"\x30")


def test_refuses_incomplete_or_mismatched(tmp_path):
    creds = load_or_create_credentials(tmp_path / "kc")
    (tmp_path / "kc" / "device_id").write_text("f" * 32)
    with pytest.raises(ValueError):
        load_or_create_credentials(tmp_path / "kc")
    os.remove(creds.key_path)
    with pytest.raises(ValueError):
        load_or_create_credentials(tmp_path / "kc")
