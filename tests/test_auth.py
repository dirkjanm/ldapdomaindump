import argparse
import pytest
from unittest.mock import patch, MagicMock

from ldapdomaindump.auth import build_connection


def _ns(**overrides):
    """Build an argparse.Namespace with sensible defaults matching main()'s parser."""
    defaults = dict(
        host='dc.example.local',
        user='EXAMPLE\\alice',
        password='hunter2',
        authtype='NTLM',
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_ntlm_bind_uses_ntlm_authentication(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_connection.return_value = mock_conn

    build_connection(_ns(authtype='NTLM'))

    kwargs = mock_connection.call_args.kwargs
    assert kwargs['user'] == 'EXAMPLE\\alice'
    assert kwargs['password'] == 'hunter2'
    # NTLM constant lives in ldap3 — compare by identity via the module
    from ldap3 import NTLM
    assert kwargs['authentication'] == NTLM


@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_simple_bind_uses_simple_authentication(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_connection.return_value = mock_conn

    build_connection(_ns(authtype='SIMPLE'))

    kwargs = mock_connection.call_args.kwargs
    assert kwargs['authentication'] == 'SIMPLE'


@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_failed_bind_raises(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = False
    mock_conn.result = {'result': 49, 'description': 'invalidCredentials'}
    mock_connection.return_value = mock_conn

    with pytest.raises(RuntimeError) as exc:
        build_connection(_ns())
    assert 'invalidCredentials' in str(exc.value)


@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_anonymous_bind_passes_no_auth_kwargs(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_connection.return_value = mock_conn

    build_connection(_ns(user=None, password=None))

    _, kwargs = mock_connection.call_args
    assert 'user' not in kwargs
    assert 'password' not in kwargs
    assert 'authentication' not in kwargs
