import pytest
from ldapdomaindump.authentication import ADAuthentication


def test_init_splits_upn_username():
    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='target.local', auth_method='auto',
                            ldap_channel_binding=False)
    assert auth.username == 'alice'
    assert auth.userdomain == 'corp.local'
    assert auth.domain == 'target.local'


def test_init_domain_lowercased():
    auth = ADAuthentication(username='alice', password='pw',
                            domain='CORP.LOCAL', auth_method='auto',
                            ldap_channel_binding=False)
    assert auth.domain == 'corp.local'
    assert auth.userdomain == 'corp.local'


def test_init_sets_defaults():
    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False)
    assert auth.tgt is None
    assert auth.lm_hash == ''
    assert auth.nt_hash == ''
    assert auth.aeskey == ''
    assert auth.use_ccache is False


def test_set_kdc_syncs_userdomain_kdc_when_same_domain():
    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='corp.local', auth_method='auto',
                            ldap_channel_binding=False)
    auth.set_kdc('dc.corp.local')
    assert auth.kdc == 'dc.corp.local'
    assert auth.userdomain_kdc == 'dc.corp.local'


def test_set_kdc_does_not_sync_when_cross_realm():
    auth = ADAuthentication(username='alice@user.local', password='pw',
                            domain='target.local', auth_method='auto',
                            ldap_channel_binding=False)
    auth.set_kdc('dc.target.local')
    assert auth.kdc == 'dc.target.local'
    assert auth.userdomain_kdc == 'user.local'


def test_set_aeskey():
    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False)
    auth.set_aeskey('a' * 64)
    assert auth.aeskey == 'a' * 64


from unittest.mock import MagicMock, patch


@patch.dict('os.environ', {'KRB5CCNAME': '/tmp/krb5cc_nope'})
@patch('ldapdomaindump.authentication.os.path.isfile', return_value=False)
def test_load_ccache_missing_file_returns_false(mock_isfile):
    auth = ADAuthentication(username='alice', password='', domain='corp.local',
                            auth_method='kerberos', ldap_channel_binding=False)
    assert auth.load_ccache() is False


@patch('ldapdomaindump.authentication.os.path.isfile', return_value=True)
@patch('ldapdomaindump.authentication.CCache')
@patch.dict('os.environ', {'KRB5CCNAME': '/tmp/krb5cc_test'})
def test_load_ccache_selects_krbtgt_principal(mock_ccache_cls, mock_isfile):
    # Set up fake ccache with a matching TGT credential
    fake_creds = MagicMock()
    fake_tgt_dict = {'KDC_REP': b'\x00' * 64,
                     'cipher': MagicMock(),
                     'sessionKey': MagicMock()}
    fake_creds.toTGT.return_value = fake_tgt_dict
    fake_ccache = MagicMock()
    fake_ccache.getCredential.return_value = fake_creds
    mock_ccache_cls.loadFile.return_value = fake_ccache

    auth = ADAuthentication(username='alice', password='', domain='corp.local',
                            auth_method='kerberos', ldap_channel_binding=False)

    # Patch the ticket-principal-verification helpers so we don't decode bogus ASN.1
    with patch('ldapdomaindump.authentication.decoder.decode') as mock_decode, \
         patch('ldapdomaindump.authentication.Ticket'), \
         patch('ldapdomaindump.authentication.Principal') as mock_principal_cls:
        mock_decode.return_value = (MagicMock(), None)
        matching_principal = MagicMock()
        matching_principal.__str__ = lambda self: 'alice@CORP.LOCAL'
        mock_principal_cls.return_value = matching_principal

        result = auth.load_ccache()

    mock_ccache_cls.loadFile.assert_called_once_with('/tmp/krb5cc_test')
    fake_ccache.getCredential.assert_called_once_with(
        'krbtgt/CORP.LOCAL@CORP.LOCAL', anySPN=False)
    assert auth.tgt == fake_tgt_dict
    assert result is True


@patch('ldapdomaindump.authentication.os.path.isfile', return_value=True)
@patch('ldapdomaindump.authentication.CCache')
@patch.dict('os.environ', {'KRB5CCNAME': '/tmp/krb5cc_test'})
def test_load_ccache_no_matching_credential_returns_false(mock_ccache_cls, mock_isfile):
    fake_ccache = MagicMock()
    fake_ccache.getCredential.return_value = None
    mock_ccache_cls.loadFile.return_value = fake_ccache

    auth = ADAuthentication(username='alice', password='', domain='corp.local',
                            auth_method='kerberos', ldap_channel_binding=False)
    assert auth.load_ccache() is False
