import argparse
import re
import ssl
import pytest
from unittest.mock import patch, MagicMock

from ldap3 import NTLM
from ldapdomaindump.auth import build_connection, _build_server, AuthError


def _ns(**overrides):
    defaults = dict(
        host='dc.example.local',
        username='alice@example.local',
        password='hunter2',
        auth_method='auto',
        kerberos=False,
        hashes=None,
        no_pass=False,
        aesKey=None,
        domain=None,
        ldap_channel_binding=False,
        no_tls_verify=False,
        start_tls=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


@patch('ldapdomaindump.auth.ADAuthentication')
def test_build_connection_wires_upn_username_into_adauthentication(mock_cls):
    build_connection(_ns(username='alice@example.local', auth_method='ntlm'))
    _, kwargs = mock_cls.call_args
    assert kwargs['username'] == 'alice@example.local'
    assert kwargs['domain'] == 'example.local'


@patch('ldapdomaindump.auth.ADAuthentication')
def test_build_connection_uses_domain_flag_when_no_at_sign(mock_cls):
    build_connection(_ns(username='alice', domain='CORP', auth_method='ntlm'))
    _, kwargs = mock_cls.call_args
    assert kwargs['username'] == 'alice'
    assert kwargs['domain'] == 'CORP'


def test_build_connection_rejects_downlevel_username():
    with pytest.raises(AuthError) as exc:
        build_connection(_ns(username='EXAMPLE\\alice'))
    msg = str(exc.value)
    assert 'UPN' in msg or 'user@domain' in msg
    assert 'DOMAIN\\user' in msg or 'down-level' in msg.lower()


def test_build_connection_rejects_username_without_realm_and_no_domain():
    with pytest.raises(AuthError) as exc:
        build_connection(_ns(username='alice', domain=None))
    assert 'realm' in str(exc.value) or 'user@domain' in str(exc.value)


def test_build_connection_rejects_ip_host_when_kerberos_required():
    with pytest.raises(AuthError) as exc:
        build_connection(_ns(host='10.0.0.1', auth_method='kerberos'))
    msg = str(exc.value)
    assert 'FQDN' in msg or 'hostname' in msg


@patch('ldapdomaindump.auth.ADAuthentication')
def test_build_connection_passes_kdc_from_host(mock_cls):
    build_connection(_ns(host='ldaps://dc.example.local:636', auth_method='ntlm'))
    mock_cls.return_value.set_kdc.assert_called_once_with('dc.example.local')


@patch('ldapdomaindump.auth.ADAuthentication')
def test_build_connection_passes_use_ccache_when_kerberos_flag(mock_cls):
    build_connection(_ns(kerberos=True, auth_method='kerberos'))
    _, kwargs = mock_cls.call_args
    assert kwargs['use_ccache'] is True


@patch('ldapdomaindump.auth.ADAuthentication')
def test_build_connection_calls_set_aeskey_when_provided(mock_cls):
    build_connection(_ns(aesKey='a' * 64))
    mock_cls.return_value.set_aeskey.assert_called_once_with('a' * 64)


@patch('ldapdomaindump.auth.ADAuthentication')
def test_build_connection_passes_hashes_split(mock_cls):
    build_connection(_ns(hashes='aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'))
    _, kwargs = mock_cls.call_args
    assert kwargs['lm_hash'] == 'aad3b435b51404eeaad3b435b51404ee'
    assert kwargs['nt_hash'] == '31d6cfe0d16ae931b73c59d7e0c089c0'


@patch('ldapdomaindump.auth.ADAuthentication')
def test_build_connection_anonymous_skips_kdc_fqdn_check(mock_cls):
    # No username → no Kerberos will be attempted → IP host is fine.
    build_connection(_ns(host='10.0.0.1', username=None, auth_method='auto'))
    mock_cls.return_value.authenticate.assert_called_once()


def test_build_server_defaults_to_validating_tls():
    args = _ns(host='ldaps://dc.example.local', no_tls_verify=False)
    server = _build_server(args)
    assert server.ssl is True
    assert server.tls is not None
    assert server.tls.validate == ssl.CERT_REQUIRED


def test_build_server_no_tls_verify_disables_validation(capfd):
    args = _ns(host='ldaps://dc.example.local', no_tls_verify=True)
    server = _build_server(args)
    assert server.tls.validate == ssl.CERT_NONE
    out, err = capfd.readouterr()
    assert 'TLS certificate validation disabled' in (out + err)


def test_build_server_plain_ldap_has_no_ssl():
    args = _ns(host='dc.example.local', no_tls_verify=False)
    server = _build_server(args)
    assert server.ssl is False
