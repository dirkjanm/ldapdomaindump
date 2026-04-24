"""Shared test fixtures / fakes for ADAuthentication tests."""
from unittest.mock import MagicMock


def fake_tgt():
    """Return a `tgt` dict with the shape ADAuthentication expects."""
    cipher = MagicMock(name='cipher')
    cipher.enctype = 18  # aes256-cts-hmac-sha1-96
    return {
        'KDC_REP': b'\x00' * 64,
        'cipher': cipher,
        'sessionKey': MagicMock(name='sessionKey'),
    }
