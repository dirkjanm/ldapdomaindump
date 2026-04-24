import pytest
from binascii import unhexlify
from ldapdomaindump.authentication import ADAuthentication
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED


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


from tests.fixtures import fake_tgt


@patch('ldapdomaindump.authentication.CheckSumField')
@patch('ldapdomaindump.authentication.bind_operation', return_value='bind_req_obj')
@patch('ldapdomaindump.authentication.encoder')
@patch('ldapdomaindump.authentication.seq_set')
@patch('ldapdomaindump.authentication.Authenticator')
@patch('ldapdomaindump.authentication.AP_REQ')
@patch('ldapdomaindump.authentication.Ticket')
@patch('ldapdomaindump.authentication.decoder')
@patch('ldapdomaindump.authentication.getKerberosTGS')
def test_ldap_kerberos_fetches_ldap_tgs_and_sends_bind(
        mock_get_tgs, mock_decoder, mock_ticket_cls, mock_ap_req_cls,
        mock_auth_cls, mock_seq_set, mock_encoder, mock_bind_op, mock_chk_cls):
    mock_get_tgs.return_value = (b'LDAP_TGS_BYTES',
                                 MagicMock(enctype=18), None, MagicMock())
    mock_decoder.decode.return_value = (MagicMock(), None)
    mock_encoder.encode.side_effect = [b'ENCODED_AUTH', b'ENCODED_APREQ']

    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='corp.local', auth_method='kerberos',
                            ldap_channel_binding=False, kdc='dc.corp.local')
    auth.tgt = fake_tgt()

    fake_conn = MagicMock()
    fake_conn.version = 3
    fake_conn.socket.getpeercert.side_effect = AttributeError  # no TLS
    fake_conn.post_send_single_response.return_value = [{'result': 0}]

    ok = auth.ldap_kerberos(fake_conn, 'dc.corp.local')

    assert ok is True
    assert fake_conn.bound is True
    fake_conn.refresh_server_info.assert_called_once()
    # TGS requested with servername ldap/<hostname>
    args, _ = mock_get_tgs.call_args
    servername = args[0]
    assert str(servername).startswith('ldap/')


@patch('ldapdomaindump.authentication.CheckSumField')
@patch('ldapdomaindump.authentication.bind_operation', return_value='bind_req_obj')
@patch('ldapdomaindump.authentication.encoder')
@patch('ldapdomaindump.authentication.seq_set')
@patch('ldapdomaindump.authentication.Authenticator')
@patch('ldapdomaindump.authentication.AP_REQ')
@patch('ldapdomaindump.authentication.Ticket')
@patch('ldapdomaindump.authentication.decoder')
@patch('ldapdomaindump.authentication.getKerberosTGS')
def test_ldap_kerberos_returns_false_on_nonzero_result(
        mock_get_tgs, mock_decoder, mock_ticket_cls, mock_ap_req_cls,
        mock_auth_cls, mock_seq_set, mock_encoder, mock_bind_op, mock_chk_cls):
    mock_get_tgs.return_value = (b'LDAP_TGS_BYTES',
                                 MagicMock(enctype=18), None, MagicMock())
    mock_decoder.decode.return_value = (MagicMock(), None)
    mock_encoder.encode.side_effect = [b'ENCODED_AUTH', b'ENCODED_APREQ']

    auth = ADAuthentication(username='alice@corp.local', password='pw',
                            domain='corp.local', auth_method='kerberos',
                            ldap_channel_binding=False, kdc='dc.corp.local')
    auth.tgt = fake_tgt()

    fake_conn = MagicMock()
    fake_conn.version = 3
    fake_conn.socket.getpeercert.side_effect = AttributeError
    fake_conn.post_send_single_response.return_value = [{'result': 49}]

    ok = auth.ldap_kerberos(fake_conn, 'dc.corp.local')
    assert ok is False
    fake_conn.refresh_server_info.assert_not_called()


def test_compute_channel_bindings_no_tls_returns_none():
    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='kerberos', ldap_channel_binding=False)
    conn = MagicMock()
    conn.socket.getpeercert.side_effect = AttributeError
    assert auth._compute_channel_bindings(conn) is None


def test_compute_channel_bindings_empty_peercert_returns_none():
    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='kerberos', ldap_channel_binding=False)
    conn = MagicMock()
    conn.socket.getpeercert.return_value = b''
    assert auth._compute_channel_bindings(conn) is None


def test_compute_channel_bindings_with_peercert_produces_16_byte_md5():
    """Feed a real DER cert through the computation — result is md5 = 16 bytes."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes as c_hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime as _dt

    # Generate a throwaway self-signed cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test')])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(_dt.datetime.utcnow())
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=1))
            .sign(key, c_hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)

    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='kerberos', ldap_channel_binding=False)
    conn = MagicMock()
    conn.socket.getpeercert.return_value = der

    bindings = auth._compute_channel_bindings(conn)
    assert bindings is not None
    assert isinstance(bindings, bytes)
    assert len(bindings) == 16


def test_kerberos_usable_needs_username():
    auth = ADAuthentication(username='', password='pw', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False)
    assert auth._kerberos_usable() is False


def test_kerberos_usable_with_password():
    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False)
    assert auth._kerberos_usable() is True


def test_kerberos_usable_with_ccache():
    auth = ADAuthentication(username='alice', password='', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False,
                            use_ccache=True)
    assert auth._kerberos_usable() is True


def test_kerberos_forced_true_when_use_ccache():
    auth = ADAuthentication(username='alice', password='', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False,
                            use_ccache=True)
    assert auth._kerberos_forced() is True


def test_kerberos_forced_false_otherwise():
    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False)
    assert auth._kerberos_forced() is False


@patch('ldapdomaindump.authentication.Connection')
def test_authenticate_anonymous(mock_conn_cls):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_conn_cls.return_value = mock_conn

    auth = ADAuthentication(username='', password='', domain='corp.local',
                            auth_method='auto', ldap_channel_binding=False)
    server = MagicMock()
    result = auth.authenticate(server, 'dc.corp.local')
    assert result is mock_conn
    # Anonymous bind: Connection called with only server positional
    mock_conn_cls.assert_called_once_with(server)


@patch('ldapdomaindump.authentication.Connection')
def test_authenticate_ntlm_path(mock_conn_cls):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_conn_cls.return_value = mock_conn

    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='ntlm', ldap_channel_binding=False)
    server = MagicMock()
    auth.authenticate(server, 'dc.corp.local')

    _, kwargs = mock_conn_cls.call_args
    assert kwargs['user'] == 'corp.local\\alice'
    assert kwargs['password'] == 'pw'
    from ldap3 import NTLM
    assert kwargs['authentication'] == NTLM
    assert 'channel_binding' not in kwargs


@patch('ldapdomaindump.authentication.Connection')
def test_authenticate_ntlm_strongerauthrequired_raises(mock_conn_cls):
    from ldapdomaindump.auth import AuthError
    mock_conn = MagicMock()
    mock_conn.bind.return_value = False
    mock_conn.result = {'result': RESULT_STRONGER_AUTH_REQUIRED}
    mock_conn_cls.return_value = mock_conn

    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='ntlm', ldap_channel_binding=False)
    with pytest.raises(AuthError) as exc:
        auth.authenticate(MagicMock(), 'dc.corp.local')
    assert 'NTLM bind rejected' in str(exc.value)


@patch('ldapdomaindump.authentication.Connection')
def test_authenticate_ldap_channel_binding_missing_ldap3_attr_raises(mock_conn_cls, monkeypatch):
    from ldapdomaindump.auth import AuthError
    # Simulate ldap3 without TLS_CHANNEL_BINDING
    monkeypatch.delattr('ldapdomaindump.authentication.ldap3.TLS_CHANNEL_BINDING', raising=False)

    auth = ADAuthentication(username='alice', password='pw', domain='corp.local',
                            auth_method='ntlm', ldap_channel_binding=True)
    with pytest.raises(AuthError) as exc:
        auth.authenticate(MagicMock(), 'dc.corp.local')
    assert 'patched ldap3' in str(exc.value)


def test_authenticate_kerberos_branch_falls_through_is_bug():
    # Safety: if auth_method == 'kerberos' and _kerberos_usable() is False,
    # validation should have already failed — but the class should still raise
    # rather than continue to NTLM.
    from ldapdomaindump.auth import AuthError
    auth = ADAuthentication(username='', password='', domain='corp.local',
                            auth_method='kerberos', ldap_channel_binding=False)
    with pytest.raises(AuthError):
        auth.authenticate(MagicMock(), 'dc.corp.local')
