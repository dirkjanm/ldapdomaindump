"""Active Directory authentication helper.

Ported from BloodHound.py (bloodhound/ad/authentication.py) with pruning:
no Global Catalog, no SMB TGS, no BH.py DNS/DC discovery.
"""
import datetime
import logging
import os
import ssl
import traceback
from binascii import unhexlify
from hashlib import md5

import ldap3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REP, Authenticator, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.gssapi import (
    CheckSumField,
    GSS_C_MUTUAL_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
)
from impacket.krb5.kerberosv5 import (
    KerberosError,
    getKerberosTGS,
    getKerberosTGT,
)
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap3 import KERBEROS, SASL, Connection
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.operation.bind import bind_operation
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue


log = logging.getLogger(__name__)


class ADAuthentication(object):
    def __init__(self, username='', password='', domain='', auth_method='auto',
                 ldap_channel_binding=False, lm_hash='', nt_hash='', aeskey='',
                 kdc=None, use_ccache=False):
        self.username = username
        self.domain = domain.lower() if domain else ''
        self.userdomain = self.domain
        if '@' in self.username:
            self.username, self.userdomain = self.username.lower().rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash or ''
        self.nt_hash = nt_hash or ''
        self.aeskey = aeskey or ''
        self.kdc = kdc
        self.userdomain_kdc = self.userdomain
        self.auth_method = auth_method
        self.ldap_channel_binding = ldap_channel_binding
        self.use_ccache = use_ccache
        self.tgt = None

    def set_aeskey(self, aeskey):
        self.aeskey = aeskey

    def set_kdc(self, kdc):
        self.kdc = kdc
        if self.userdomain == self.domain:
            self.userdomain_kdc = kdc

    def load_ccache(self):
        """Load TGT from a Kerberos credential cache file ($KRB5CCNAME)."""
        krb5cc = os.getenv('KRB5CCNAME')
        if krb5cc is None:
            try:
                krb5cc = '/tmp/krb5cc_%u' % os.getuid()
            except AttributeError:
                krb5cc = 'nonexistingfile'

        if not os.path.isfile(krb5cc):
            log.debug('No Kerberos credential cache file found at %s', krb5cc)
            return False

        log.debug('Using kerberos credential cache: %s', krb5cc)
        ccache = CCache.loadFile(krb5cc)
        principal = 'krbtgt/%s@%s' % (self.domain.upper(), self.domain.upper())
        creds = ccache.getCredential(principal, anySPN=False)
        if creds is None:
            log.debug('No valid credentials found in cache for %s', principal)
            return False

        tgt_dict = creds.toTGT()
        self.tgt = tgt_dict

        # Verify ticket principal matches supplied username
        tgt_bytes = tgt_dict['KDC_REP']
        decoded_tgt = decoder.decode(tgt_bytes, asn1Spec=AS_REP())[0]
        tgt_principal = Principal()
        tgt_principal.from_asn1(decoded_tgt, 'crealm', 'cname')
        expected = '%s@%s' % (self.username.lower(), self.domain.upper())
        if expected.upper() != str(tgt_principal).upper():
            log.warning('Username in ccache does not match supplied username: %s != %s',
                        tgt_principal, expected)
            return False
        log.info('Found TGT with correct principal in ccache')
        return True

    def get_tgt(self):
        """Request a Kerberos TGT using our provided credentials."""
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        log.info('Getting TGT for user')
        try:
            tgt, cipher, _, session_key = getKerberosTGT(
                username, self.password, self.userdomain,
                unhexlify(self.lm_hash), unhexlify(self.nt_hash),
                self.aeskey, self.userdomain_kdc)
        except Exception as exc:
            log.debug(traceback.format_exc())
            if self.auth_method == 'auto':
                log.warning('Failed to get Kerberos TGT; will fall back to NTLM: %s', exc)
                return
            log.error('Failed to get Kerberos TGT.')
            raise

        if self.userdomain != self.domain:
            self._get_cross_realm_tgt(tgt, cipher, session_key)
        else:
            self.tgt = {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': session_key}

    def _get_cross_realm_tgt(self, tgt, cipher, session_key):
        """Walk krbtgt referrals until we land in the target realm, then store as self.tgt.

        Propagates KerberosError (and underlying network exceptions) from getKerberosTGS;
        the caller (get_tgt) is responsible for auth_method-aware handling.
        """
        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)  # noqa: F841
        servername = Principal('krbtgt/%s' % self.domain,
                               type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, sessionkey = getKerberosTGS(
            servername, self.userdomain, self.userdomain_kdc, tgt, cipher, session_key)

        while True:
            decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
            next_realm = str(decoded_tgs['ticket']['sname']['name-string'][1])
            if next_realm.upper() == self.domain.upper():
                break
            log.debug('Following referral across trust to get next TGT')
            servername = Principal('krbtgt/%s' % self.domain,
                                   type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, _, sessionkey = getKerberosTGS(
                servername, next_realm, next_realm, tgs, cipher, sessionkey)

        servername = Principal('krbtgt/%s' % self.domain,
                               type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, sessionkey = getKerberosTGS(
            servername, self.domain, self.kdc, tgs, cipher, sessionkey)
        self.tgt = {'KDC_REP': tgs, 'cipher': cipher, 'sessionKey': sessionkey}

    def ldap_kerberos(self, connection, hostname):
        """Bind `connection` using our TGT, via SASL GSSAPI with an impacket-built AP-REQ."""
        connection.open(read_server_info=False)

        username = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        servername = Principal('ldap/%s' % hostname,
                               type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, sessionkey = getKerberosTGS(
            servername, self.domain, self.kdc,
            self.tgt['KDC_REP'], self.tgt['cipher'], self.tgt['sessionKey'])

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        apReq['ap-options'] = constants.encodeFlags([])
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.userdomain
        seq_set(authenticator, 'cname', username.components_to_asn1)
        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        bindings = self._compute_channel_bindings(connection)

        authenticator['cksum'] = noValue
        authenticator['cksum']['cksumtype'] = 0x8003
        chkField = CheckSumField()
        chkField['Lgth'] = 16
        if bindings:
            chkField['Bnd'] = bindings
        chkField['Flags'] = 0
        authenticator['cksum']['checksum'] = chkField.getData()

        encoded_auth = encoder.encode(authenticator)
        encrypted_auth = cipher.encrypt(sessionkey, 11, encoded_auth, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encrypted_auth

        blob['MechToken'] = encoder.encode(apReq)

        request = bind_operation(connection.version, SASL, None, None,
                                 connection.sasl_mechanism, blob.getData())
        response = connection.post_send_single_response(
            connection.send('bindRequest', request, None))[0]
        connection.result = response
        if response['result'] == 0:
            connection.bound = True
            connection.refresh_server_info()
        return response['result'] == 0

    def _compute_channel_bindings(self, connection):
        """RFC 5929 tls-server-end-point channel bindings → GSS MD5.

        Returns 16-byte MD5 or None if no TLS / no peercert.
        """
        try:
            peercert = connection.socket.getpeercert(binary_form=True)
        except AttributeError:
            return None
        if not peercert:
            return None

        peer_certificate = x509.load_der_x509_certificate(peercert, default_backend())
        peer_hash_algo = peer_certificate.signature_hash_algorithm

        rfc5929_weak = (hashes.MD5, hashes.SHA1)
        if isinstance(peer_hash_algo, rfc5929_weak):
            digest = hashes.Hash(hashes.SHA256(), default_backend())
        else:
            digest = hashes.Hash(peer_hash_algo, default_backend())
        digest.update(peercert)
        peer_digest = digest.finalize()

        initiator_address = b'\x00' * 8
        acceptor_address = b'\x00' * 8
        application_data_raw = b'tls-server-end-point:' + peer_digest
        application_data = len(application_data_raw).to_bytes(4, byteorder='little', signed=False)
        application_data += application_data_raw

        channel_binding_struct = initiator_address + acceptor_address + application_data
        return md5(channel_binding_struct).digest()
