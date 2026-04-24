import pytest
from binascii import unhexlify
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


@patch('ldapdomaindump.authentication.getKerberosTGT')
def test_get_tgt_single_realm_populates_self_tgt(mock_get_tgt):
    cipher = MagicMock()
    session_key = MagicMock()
    mock_get_tgt.return_value = (b'TGT_BYTES', cipher, None, session_key)

    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='corp.local', auth_method='kerberos',
                            ldap_channel_binding=False, kdc='dc.corp.local')
    auth.userdomain_kdc = 'dc.corp.local'

    auth.get_tgt()

    assert auth.tgt == {
        'KDC_REP': b'TGT_BYTES',
        'cipher': cipher,
        'sessionKey': session_key,
    }
    # Signature per impacket: (principal, password, domain, lm_hash_bytes, nt_hash_bytes, aeskey, kdc)
    args, _ = mock_get_tgt.call_args
    principal, password, domain, lm_bytes, nt_bytes, aeskey, kdc = args
    assert str(principal) == 'alice'
    assert password == 'pw'
    assert domain == 'corp.local'
    assert lm_bytes == b''
    assert nt_bytes == b''
    assert aeskey == ''
    assert kdc == 'dc.corp.local'


@patch('ldapdomaindump.authentication.getKerberosTGT',
       side_effect=Exception('pre-auth failed'))
def test_get_tgt_raises_when_auth_method_kerberos(mock_get_tgt):
    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='corp.local', auth_method='kerberos',
                            ldap_channel_binding=False, kdc='dc.corp.local')
    with pytest.raises(Exception):
        auth.get_tgt()


@patch('ldapdomaindump.authentication.getKerberosTGT',
       side_effect=Exception('pre-auth failed'))
def test_get_tgt_returns_silently_when_auto(mock_get_tgt):
    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='corp.local', auth_method='auto',
                            ldap_channel_binding=False, kdc='dc.corp.local')
    # auto mode: BH.py swallows the exception and returns so the caller can fall back
    auth.get_tgt()
    assert auth.tgt is None


@patch('ldapdomaindump.authentication.getKerberosTGT')
def test_get_tgt_unhexlifies_hashes(mock_get_tgt):
    mock_get_tgt.return_value = (b'TGT', MagicMock(), None, MagicMock())
    auth = ADAuthentication(username='alice@corp.local', password='',
                            domain='corp.local', auth_method='kerberos',
                            ldap_channel_binding=False, kdc='dc.corp.local',
                            lm_hash='aad3b435b51404eeaad3b435b51404ee',
                            nt_hash='31d6cfe0d16ae931b73c59d7e0c089c0')
    auth.userdomain_kdc = 'dc.corp.local'
    auth.get_tgt()

    args, _ = mock_get_tgt.call_args
    _, _, _, lm_bytes, nt_bytes, _, _ = args
    assert lm_bytes == unhexlify('aad3b435b51404eeaad3b435b51404ee')
    assert nt_bytes == unhexlify('31d6cfe0d16ae931b73c59d7e0c089c0')


@patch('ldapdomaindump.authentication.getKerberosTGS')
@patch('ldapdomaindump.authentication.getKerberosTGT')
def test_get_tgt_cross_realm_walks_referrals(mock_get_tgt, mock_get_tgs):
    mock_get_tgt.return_value = (b'USER_TGT', MagicMock(), None, MagicMock())
    # Three TGS calls: initial referral, one intermediate ticket in wrong realm,
    # final foreign-domain TGT.
    mock_get_tgs.side_effect = [
        (b'REFERRAL_TGS_1', MagicMock(), None, MagicMock()),
        (b'REFERRAL_TGS_2', MagicMock(), None, MagicMock()),
        (b'FOREIGN_TGT', MagicMock(), None, MagicMock()),
    ]

    # Patch decode to return a sequence of sname realms: first intermediate (wrong),
    # then the target realm (correct).
    def fake_decode(data, asn1Spec=None):
        # Return a structure whose ['ticket']['sname']['name-string'][1] is a
        # realm string. We flip between realms based on what bytes were passed in.
        ticket = {'sname': {'name-string': ['ldap', 'intermediate.local' if data == b'REFERRAL_TGS_1' else 'target.local']}}
        return ({'ticket': ticket},)

    with patch('ldapdomaindump.authentication.decoder.decode', side_effect=fake_decode):
        auth = ADAuthentication(username='alice@user.local', password='pw',
                                domain='target.local', auth_method='kerberos',
                                ldap_channel_binding=False, kdc='dc.target.local')
        auth.userdomain_kdc = 'dc.user.local'
        auth.get_tgt()

    assert auth.tgt['KDC_REP'] == b'FOREIGN_TGT'
    assert mock_get_tgs.call_count == 3
