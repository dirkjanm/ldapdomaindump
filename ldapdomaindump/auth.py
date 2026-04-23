"""Authentication helpers for ldapdomaindump.

All LDAP bind logic lives here behind build_connection(args). main() is
expected to call build_connection() once and hand the resulting bound
Connection to domainDumper.
"""
from ldap3 import Server, Connection, ALL, NTLM

# ldap3 2.x does not export ENCRYPT; define a sentinel used as the
# session_security value to request NTLM sign/seal on plain LDAP.
# Over TLS this is a no-op because the transport already encrypts.
ENCRYPT = 'ENCRYPT'


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
        session_security=ENCRYPT,
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


def _do_bind(conn):
    if not conn.bind():
        raise AuthError('Bind failed: %s' % conn.result)
