import pytest
from ldapdomaindump import _build_parser


def test_no_tls_verify_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--no-tls-verify', 'dc.example.local'])
    assert args.no_tls_verify is True


def test_no_tls_verify_defaults_to_false():
    parser = _build_parser()
    args = parser.parse_args(['dc.example.local'])
    assert args.no_tls_verify is False


def test_start_tls_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--start-tls', 'dc.example.local'])
    assert args.start_tls is True


def test_start_tls_with_ldaps_url_rejected(capsys):
    from ldapdomaindump import _validate_args
    parser = _build_parser()
    args = parser.parse_args(['--start-tls', 'ldaps://dc.example.local'])
    with pytest.raises(SystemExit):
        _validate_args(parser, args)
    err = capsys.readouterr().err
    assert '--start-tls' in err
    assert 'ldaps://' in err
