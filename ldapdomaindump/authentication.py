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
