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
        """Placeholder — cross-realm TGT walking added in the next task."""
        raise NotImplementedError('cross-realm TGT handling not yet implemented')
