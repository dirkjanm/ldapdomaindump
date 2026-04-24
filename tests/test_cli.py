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


def test_auth_method_default_is_auto():
    parser = _build_parser()
    args = parser.parse_args(['dc.example.local'])
    assert args.auth_method == 'auto'


def test_kerberos_short_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['-k', 'dc.example.local'])
    assert args.kerberos is True


def test_no_pass_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['-no-pass', 'dc.example.local'])
    assert args.no_pass is True


def test_hashes_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--hashes', 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0', 'dc.example.local'])
    assert args.hashes == 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'


def test_aeskey_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['-aesKey', 'a' * 64, 'dc.example.local'])
    assert args.aesKey == 'a' * 64


def test_domain_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--domain', 'CORP', 'dc.example.local'])
    assert args.domain == 'CORP'


def test_ldap_channel_binding_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--ldap-channel-binding', 'dc.example.local'])
    assert args.ldap_channel_binding is True


def test_at_authtype_flag_removed():
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(['-at', 'NTLM', 'dc.example.local'])


def test_hashes_malformed_rejected(capsys):
    from ldapdomaindump import _validate_args
    parser = _build_parser()
    args = parser.parse_args(['--hashes', 'notahash', 'dc.example.local'])
    with pytest.raises(SystemExit):
        _validate_args(parser, args)
    err = capsys.readouterr().err
    assert '--hashes' in err
    assert 'LM:NT' in err


def test_hashes_valid_passes():
    from ldapdomaindump import _validate_args
    parser = _build_parser()
    args = parser.parse_args(['--hashes', 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0', 'dc.example.local'])
    _validate_args(parser, args)  # no exit


def test_aeskey_wrong_length_rejected(capsys):
    from ldapdomaindump import _validate_args
    parser = _build_parser()
    args = parser.parse_args(['-aesKey', 'abcd', 'dc.example.local'])
    with pytest.raises(SystemExit):
        _validate_args(parser, args)
    err = capsys.readouterr().err
    assert 'aesKey' in err
    assert '32 or 64 hex' in err


def test_aeskey_aes128_accepted():
    from ldapdomaindump import _validate_args
    parser = _build_parser()
    args = parser.parse_args(['-aesKey', 'a' * 32, 'dc.example.local'])
    _validate_args(parser, args)


def test_aeskey_aes256_accepted():
    from ldapdomaindump import _validate_args
    parser = _build_parser()
    args = parser.parse_args(['-aesKey', 'b' * 64, 'dc.example.local'])
    _validate_args(parser, args)
