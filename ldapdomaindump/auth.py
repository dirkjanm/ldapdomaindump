"""Authentication helpers for ldapdomaindump.

All LDAP bind logic lives here behind build_connection(args). main() is
expected to call build_connection() once and hand the resulting bound
Connection to domainDumper.
"""
from ldap3 import Server, Connection, ALL, NTLM


class AuthError(RuntimeError):
    """Raised when authentication cannot be completed."""


def build_connection(args):
    """Build and bind an ldap3.Connection from parsed CLI args.

    Returns the bound Connection. Raises AuthError on any failure.
    """
    server = Server(args.host, get_info=ALL)

    if args.user is None:
        return _bind_anonymous(server)

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
    )
    _do_bind(conn)
    return conn


def _bind_simple(server, args):
    conn = Connection(
        server,
        user=args.user,
        password=args.password,
        authentication='SIMPLE',
    )
    _do_bind(conn)
    return conn


def _bind_anonymous(server):
    conn = Connection(server)
    _do_bind(conn)
    return conn


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
        if conn.authentication == 'SIMPLE':
            raise AuthError(_SIMPLE_SIGNING_HINT)
        if conn.authentication == NTLM:
            raise AuthError(_NTLM_SIGNING_HINT)
    raise AuthError('Bind failed: %s' % result)
