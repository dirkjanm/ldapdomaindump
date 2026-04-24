"""Authentication helpers for ldapdomaindump.

All LDAP bind logic lives here behind build_connection(args). main() is
expected to call build_connection() once and hand the resulting bound
Connection to domainDumper.
"""
import ssl
import sys

from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls


class AuthError(RuntimeError):
    """Raised when authentication cannot be completed."""


def _build_server(args):
    """Build an ldap3.Server with appropriate TLS settings.

    Detects ldaps:// scheme and ssl from the host string. If the user passed
    --no-tls-verify, disable certificate validation and warn loudly.
    """
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


def build_connection(args):
    """Build and bind an ldap3.Connection from parsed CLI args.

    Returns the bound Connection. Raises AuthError on any failure.
    """
    server = _build_server(args)

    if args.user is None:
        return _bind_anonymous(server, args)

    authtype = getattr(args, 'authtype', 'NTLM')
    if authtype == 'SIMPLE':
        return _bind_simple(server, args)
    return _bind_ntlm(server, args)


def _bind_ntlm(server, args):
    conn = Connection(
        server,
        user=args.user,
        password=args.password,
        authentication=NTLM,
        auto_bind=False,
    )
    _open_and_maybe_start_tls(conn, args)
    _do_bind(conn)
    return conn


def _bind_simple(server, args):
    conn = Connection(
        server,
        user=args.user,
        password=args.password,
        authentication=SIMPLE,
        auto_bind=False,
    )
    _open_and_maybe_start_tls(conn, args)
    _do_bind(conn)
    return conn


def _bind_anonymous(server, args):
    conn = Connection(server, auto_bind=False)
    _open_and_maybe_start_tls(conn, args)
    _do_bind(conn)
    return conn


def _open_and_maybe_start_tls(conn, args):
    conn.open()
    if getattr(args, 'start_tls', False):
        conn.start_tls()


STRONGER_AUTH_REQUIRED = 8

_SIMPLE_SIGNING_HINT = (
    "SIMPLE bind rejected: server requires signing, and SIMPLE binds cannot "
    "negotiate signing. Use -k (Kerberos, which signs over plain LDAP), or "
    "use ldaps://<host> if reachable, or pass --start-tls."
)

_NTLM_SIGNING_HINT = (
    "NTLM bind rejected: server requires signing, and the installed ldap3 "
    "does not support NTLM sign/seal. Use -k (Kerberos), or use ldaps://<host> "
    "if reachable, or pass --start-tls."
)


def _do_bind(conn):
    if conn.bind():
        return
    result = conn.result or {}
    if result.get('result') == STRONGER_AUTH_REQUIRED:
        if conn.authentication == SIMPLE:
            raise AuthError(_SIMPLE_SIGNING_HINT)
        if conn.authentication == NTLM:
            raise AuthError(_NTLM_SIGNING_HINT)
    raise AuthError('Bind failed: %s' % result)
