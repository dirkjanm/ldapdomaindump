"""Authentication dispatcher for ldapdomaindump.

Parses argparse output into an ADAuthentication instance and returns a bound
ldap3.Connection via `build_connection(args)`.
"""
import re
import ssl
import sys

from ldap3 import ALL, Server, Tls

from ldapdomaindump.authentication import ADAuthentication


class AuthError(RuntimeError):
    """Raised when authentication cannot be completed."""


_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _build_server(args):
    """Build an ldap3.Server with TLS settings derived from args.host."""
    validate = ssl.CERT_NONE if getattr(args, 'no_tls_verify', False) else ssl.CERT_REQUIRED
    if validate == ssl.CERT_NONE:
        print(
            '[!] TLS certificate validation disabled. '
            'Connection is encrypted but not authenticated.',
            file=sys.stderr,
        )
    tls = Tls(validate=validate)
    use_ssl = args.host.lower().startswith('ldaps://')
    return Server(args.host, get_info=ALL, use_ssl=use_ssl, tls=tls)


def _extract_hostname(host):
    """Strip ldap[s]:// scheme and any trailing :port, return bare hostname."""
    h = host
    if '://' in h:
        h = h.split('://', 1)[1]
    if ':' in h:
        h = h.rsplit(':', 1)[0]
    return h


def _parse_username_and_domain(args):
    """Return (raw_username_for_ADAuthentication, domain)."""
    username = args.username
    if username is None:
        return None, args.domain or ''
    if '\\' in username:
        raise AuthError(
            'username must be in UPN format (user@domain), or use --domain. '
            'Down-level DOMAIN\\user is no longer supported.')
    if '@' in username:
        return username, username.rsplit('@', 1)[1]
    if args.domain:
        return username, args.domain
    raise AuthError('username must include a realm (user@domain) or use --domain')


def _kerberos_attempt_anticipated(args):
    """Will build_connection attempt Kerberos at all?"""
    if args.username is None:
        return False
    if args.auth_method == 'ntlm':
        return False
    if args.auth_method == 'kerberos':
        return True
    # auto: attempt Kerberos if any credential source is present
    import os
    return bool(args.kerberos
                or os.getenv('KRB5CCNAME')
                or args.password
                or args.hashes
                or args.aesKey)


def build_connection(args):
    """Build and bind an ldap3.Connection from parsed CLI args. Raises AuthError."""
    username, domain = _parse_username_and_domain(args)

    hostname = _extract_hostname(args.host)

    if _kerberos_attempt_anticipated(args) and _IP_RE.match(hostname):
        raise AuthError(
            'host %s looks like an IP but Kerberos requires a hostname (FQDN). '
            'Use -n/--dns-server to specify a DNS server IP if the hostname does '
            'not resolve on your default nameserver.' % hostname)

    server = _build_server(args)

    lm_hash = ''
    nt_hash = ''
    if args.hashes:
        lm_part, nt_part = args.hashes.split(':', 1)
        lm_hash = lm_part
        nt_hash = nt_part

    auth = ADAuthentication(
        username=username or '',
        password=args.password or '',
        domain=domain,
        auth_method=args.auth_method,
        ldap_channel_binding=args.ldap_channel_binding,
        lm_hash=lm_hash,
        nt_hash=nt_hash,
        aeskey=args.aesKey or '',
        use_ccache=bool(args.kerberos),
    )
    auth.set_kdc(hostname)
    if args.aesKey:
        auth.set_aeskey(args.aesKey)

    return auth.authenticate(server, hostname)
