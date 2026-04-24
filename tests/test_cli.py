import pytest
from ldapdomaindump import _build_parser  # will be introduced in this task


def test_no_tls_verify_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--no-tls-verify', 'dc.example.local'])
    assert args.no_tls_verify is True


def test_no_tls_verify_defaults_to_false():
    parser = _build_parser()
    args = parser.parse_args(['dc.example.local'])
    assert args.no_tls_verify is False
