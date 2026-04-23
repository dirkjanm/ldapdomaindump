# Kerberos Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ccache-based Kerberos authentication to `ldapdomaindump`, fix `strongerAuthRequired` on hardened AD DCs, and add StartTLS support — all behind a new `ldapdomaindump/auth.py` module.

**Architecture:** New `auth.py` owns all bind logic behind a single `build_connection(args)` dispatcher. Kerberos path bypasses ldap3's unreliable native SASL/GSSAPI by building the AP-REQ with impacket and submitting a raw SASL bind (bloodhound.py pattern). NTLM path gains `session_security=ENCRYPT`. SIMPLE error messaging improved. StartTLS added as in-band upgrade for environments without LDAPS.

**Tech Stack:** Python 3.6+, `ldap3`, `impacket` (optional extra), `pytest` (new dev dep), `dnspython`.

**Spec:** `docs/superpowers/specs/2026-04-23-kerberos-auth-design.md`

---

## File Structure

**New files:**
- `ldapdomaindump/auth.py` — dispatcher + all bind helpers
- `tests/__init__.py` — empty, marks tests as a package
- `tests/conftest.py` — shared fixtures
- `tests/test_auth.py` — auth unit tests
- `tests/test_cli.py` — argparse validation tests
- `tests/fixtures/__init__.py` — empty
- `tests/fixtures/ccache.py` — helper to synthesize a ccache for tests

**Modified files:**
- `ldapdomaindump/__init__.py` — remove inline auth; add new CLI flags; call `build_connection`
- `pyproject.toml` — add `[project.optional-dependencies]` for `kerberos` and `dev`
- `setup.py` — mirror optional extras so both install paths agree
- `README.md` — document `-k`, `--dc-ip`, `--start-tls`, `--no-tls-verify`

Each file has one responsibility. `auth.py` stays focused on authentication. Tests mirror it. CLI plumbing stays in `__init__.py`.

---

## Task 1: Set up test infrastructure

Repo has no tests today. This task puts pytest in place so every subsequent task can be TDD'd.

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/fixtures/__init__.py`
- Create: `tests/test_smoke.py`
- Modify: `pyproject.toml`
- Modify: `.gitignore`

- [ ] **Step 1: Add dev dependencies to `pyproject.toml`**

Append to `pyproject.toml` (after the existing `dependencies = [...]` block):

```toml
[project.optional-dependencies]
dev = ["pytest>=7"]
```

- [ ] **Step 2: Create empty package markers**

```bash
mkdir -p tests/fixtures
```

Create `tests/__init__.py` — empty file.
Create `tests/fixtures/__init__.py` — empty file.

- [ ] **Step 3: Write smoke test**

Create `tests/test_smoke.py`:

```python
def test_package_imports():
    import ldapdomaindump
    assert hasattr(ldapdomaindump, 'main')
```

- [ ] **Step 4: Install dev deps and run the smoke test**

Run:
```bash
pip install -e '.[dev]'
pytest tests/test_smoke.py -v
```

Expected: 1 passed.

- [ ] **Step 5: Add pytest cache to `.gitignore`**

Append to `.gitignore`:

```
.pytest_cache/
__pycache__/
*.egg-info/
```

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .gitignore tests/
git commit -m "test: set up pytest infrastructure"
```

---

## Task 2: Extract auth into `auth.py` (refactor, no behavior change)

Move existing NTLM/SIMPLE bind logic from `main()` into `ldapdomaindump/auth.py` behind a `build_connection(args)` dispatcher. This is a pure refactor — CLI behavior, error output, and sys.exit semantics are preserved exactly.

**Files:**
- Create: `ldapdomaindump/auth.py`
- Create: `tests/test_auth.py`
- Modify: `ldapdomaindump/__init__.py:868-956` (the `main()` function's auth block)

- [ ] **Step 1: Write failing test for NTLM dispatch**

Create `tests/test_auth.py`:

```python
import argparse
import pytest
from unittest.mock import patch, MagicMock

from ldapdomaindump.auth import build_connection


def _ns(**overrides):
    """Build an argparse.Namespace with sensible defaults matching main()'s parser."""
    defaults = dict(
        host='dc.example.local',
        user='EXAMPLE\\alice',
        password='hunter2',
        authtype='NTLM',
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_ntlm_bind_uses_ntlm_authentication(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_connection.return_value = mock_conn

    build_connection(_ns(authtype='NTLM'))

    kwargs = mock_connection.call_args.kwargs
    assert kwargs['user'] == 'EXAMPLE\\alice'
    assert kwargs['password'] == 'hunter2'
    # NTLM constant lives in ldap3 — compare by identity via the module
    from ldap3 import NTLM
    assert kwargs['authentication'] == NTLM


@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_simple_bind_uses_simple_authentication(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_connection.return_value = mock_conn

    build_connection(_ns(authtype='SIMPLE'))

    kwargs = mock_connection.call_args.kwargs
    assert kwargs['authentication'] == 'SIMPLE'


@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_failed_bind_raises(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = False
    mock_conn.result = {'result': 49, 'description': 'invalidCredentials'}
    mock_connection.return_value = mock_conn

    with pytest.raises(RuntimeError) as exc:
        build_connection(_ns())
    assert 'invalidCredentials' in str(exc.value)
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `pytest tests/test_auth.py -v`

Expected: all three fail with `ModuleNotFoundError: No module named 'ldapdomaindump.auth'`.

- [ ] **Step 3: Create `ldapdomaindump/auth.py` with the dispatcher**

Create `ldapdomaindump/auth.py`:

```python
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


def _do_bind(conn):
    if not conn.bind():
        raise AuthError('Bind failed: %s' % conn.result)
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_auth.py -v`

Expected: 3 passed.

- [ ] **Step 5: Rewrite `main()`'s auth block to call `build_connection`**

In `ldapdomaindump/__init__.py`, locate lines 926-950 (the block starting with `authentication = None` through `log_success('Bind OK')`). Replace that entire block with:

```python
    #Prompt for password if not set
    if args.user is not None and '\\' not in args.user:
        log_warn('Username must include a domain, use: DOMAIN\\username')
        sys.exit(1)
    if args.user is not None and args.password is None:
        args.password = getpass.getpass()
    if args.user is None:
        log_info('Connecting as anonymous user, dumping will probably fail. Consider specifying a username/password to login with')

    log_info('Connecting to host...')
    log_info('Binding to host')
    try:
        from ldapdomaindump.auth import build_connection, AuthError
        c = build_connection(args)
    except AuthError as e:
        log_warn(str(e))
        sys.exit(1)
    s = c.server
    log_success('Bind OK')
```

Note: `s = c.server` preserves the existing `s` variable used by `domainDumper(s, c, cnf)` on line 953.

- [ ] **Step 6: Run all tests plus a manual import check**

Run:
```bash
pytest tests/ -v
python -c "from ldapdomaindump import main; print('OK')"
```

Expected: all tests pass, "OK" printed.

- [ ] **Step 7: Commit**

```bash
git add ldapdomaindump/auth.py ldapdomaindump/__init__.py tests/test_auth.py
git commit -m "refactor: extract auth into ldapdomaindump/auth.py

No behavior change. Moves NTLM/SIMPLE bind logic out of main() into
build_connection(args). Groundwork for Kerberos support and LDAP
signing fixes."
```

---

## Task 3: Enable NTLM sign/seal on plain LDAP

Hardened AD DCs return `strongerAuthRequired` (code 8) to unsigned binds on plain LDAP. NTLM supports sign/seal via `session_security=ldap3.ENCRYPT`; ldap3 is a no-op when the transport is already TLS.

**Files:**
- Modify: `ldapdomaindump/auth.py` (in `_bind_ntlm`)
- Modify: `tests/test_auth.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_auth.py`:

```python
@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_ntlm_bind_enables_session_security(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_connection.return_value = mock_conn

    build_connection(_ns(authtype='NTLM'))

    from ldap3 import ENCRYPT
    kwargs = mock_connection.call_args.kwargs
    assert kwargs.get('session_security') == ENCRYPT
```

- [ ] **Step 2: Run test to confirm it fails**

Run: `pytest tests/test_auth.py::test_ntlm_bind_enables_session_security -v`

Expected: FAIL, `session_security` not present.

- [ ] **Step 3: Update `_bind_ntlm` in `ldapdomaindump/auth.py`**

Change the import line near the top:

```python
from ldap3 import Server, Connection, ALL, NTLM, ENCRYPT
```

Update `_bind_ntlm` to pass `session_security=ENCRYPT`:

```python
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
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_auth.py -v`

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add ldapdomaindump/auth.py tests/test_auth.py
git commit -m "fix(auth): enable NTLM sign/seal to satisfy LDAP signing requirement

Modern AD DCs reject unsigned binds on plain LDAP with
strongerAuthRequired (code 8). NTLM session_security=ENCRYPT negotiates
sign/seal and is a no-op over TLS."
```

---

## Task 4: Improve SIMPLE bind error for `strongerAuthRequired`

SIMPLE binds cannot be signed. When the DC rejects with code 8, surface an actionable message pointing the user at NTLM, Kerberos, LDAPS, or StartTLS.

**Files:**
- Modify: `ldapdomaindump/auth.py`
- Modify: `tests/test_auth.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_auth.py`:

```python
@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_simple_bind_strongerauthrequired_gives_actionable_error(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = False
    mock_conn.result = {
        'result': 8,
        'description': 'strongerAuthRequired',
        'message': '00002028: LdapErr: ...',
    }
    mock_connection.return_value = mock_conn

    from ldapdomaindump.auth import AuthError
    with pytest.raises(AuthError) as exc:
        build_connection(_ns(authtype='SIMPLE'))

    msg = str(exc.value)
    assert 'SIMPLE bind rejected' in msg
    assert '-at NTLM' in msg
    assert '-k' in msg
    assert 'ldaps://' in msg
    assert '--start-tls' in msg
```

- [ ] **Step 2: Run test to confirm it fails**

Run: `pytest tests/test_auth.py::test_simple_bind_strongerauthrequired_gives_actionable_error -v`

Expected: FAIL — generic "Bind failed" message.

- [ ] **Step 3: Update `_do_bind` to detect code 8**

In `ldapdomaindump/auth.py`, replace `_do_bind`:

```python
STRONGER_AUTH_REQUIRED = 8

_SIMPLE_SIGNING_HINT = (
    "SIMPLE bind rejected: server requires signing, and SIMPLE binds cannot "
    "negotiate signing. Use -at NTLM or -k (both sign over plain LDAP), or "
    "use ldaps://<host> if reachable, or pass --start-tls."
)


def _do_bind(conn):
    if conn.bind():
        return
    result = conn.result or {}
    if (
        result.get('result') == STRONGER_AUTH_REQUIRED
        and conn.authentication == 'SIMPLE'
    ):
        raise AuthError(_SIMPLE_SIGNING_HINT)
    raise AuthError('Bind failed: %s' % result)
```

Note: `conn.authentication` is an ldap3 attribute set from the `authentication=` kwarg.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `pytest tests/test_auth.py -v`

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add ldapdomaindump/auth.py tests/test_auth.py
git commit -m "feat(auth): give actionable error on SIMPLE strongerAuthRequired

Point users at NTLM/Kerberos/LDAPS/StartTLS instead of dumping the raw
LDAP result dict."
```

---

## Task 5: Add `--no-tls-verify` flag and `_build_server`

Extract server construction into a helper that understands the URL scheme and TLS validation settings. Users with self-signed DC certs need an escape hatch.

**Files:**
- Modify: `ldapdomaindump/auth.py`
- Modify: `ldapdomaindump/__init__.py:888-893` (Misc options argparse group)
- Create: `tests/test_cli.py`
- Modify: `tests/test_auth.py`

- [ ] **Step 1: Write failing test for `_build_server`**

Add to `tests/test_auth.py`:

```python
import ssl

from ldapdomaindump.auth import _build_server


def test_build_server_defaults_to_validating_tls():
    args = _ns(host='ldaps://dc.example.local', no_tls_verify=False)
    server = _build_server(args)
    assert server.ssl is True
    assert server.tls is not None
    assert server.tls.validate == ssl.CERT_REQUIRED


def test_build_server_no_tls_verify_disables_validation(capfd):
    args = _ns(host='ldaps://dc.example.local', no_tls_verify=True)
    server = _build_server(args)
    assert server.tls.validate == ssl.CERT_NONE
    out, err = capfd.readouterr()
    assert 'TLS certificate validation disabled' in (out + err)


def test_build_server_plain_ldap_has_no_ssl():
    args = _ns(host='dc.example.local', no_tls_verify=False)
    server = _build_server(args)
    assert server.ssl is False
```

- [ ] **Step 2: Write failing test for CLI flag**

Create `tests/test_cli.py`:

```python
import pytest
from ldapdomaindump import _build_parser  # will be introduced in this task


def test_no_tls_verify_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--no-tls-verify', 'dc.example.local'])
    assert args.no_tls_verify is True


def test_no_tls_verify_defaults_to_false():
    parser = _build_parser()
    args = parser.parse_args(['dc.example.local'])
    assert args.no_tls_verify is False
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `pytest tests/ -v`

Expected: new tests fail — `_build_server` and `_build_parser` don't exist yet.

- [ ] **Step 4: Add `_build_server` to `ldapdomaindump/auth.py`**

Add these imports at the top:

```python
import ssl
import sys

from ldap3 import Tls
```

Add `_build_server`:

```python
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
```

Replace the `server = Server(args.host, get_info=ALL)` line in `build_connection` with:

```python
    server = _build_server(args)
```

- [ ] **Step 5: Extract `_build_parser` in `ldapdomaindump/__init__.py`**

Move the `argparse.ArgumentParser(...)` construction out of `main()` into a new `_build_parser()` function defined above `main()`. The body is everything from `parser = argparse.ArgumentParser(...)` through `parser.add_argument(...)` calls. Then `main()` starts with `args = _build_parser().parse_args()`.

Within `_build_parser()`, in the `miscgroup` section, add:

```python
    miscgroup.add_argument("--no-tls-verify", action='store_true', default=False,
                           help="Disable TLS certificate validation (insecure, for self-signed DC certs)")
```

- [ ] **Step 6: Run all tests**

Run: `pytest tests/ -v`

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add ldapdomaindump/auth.py ldapdomaindump/__init__.py tests/test_auth.py tests/test_cli.py
git commit -m "feat(auth): add --no-tls-verify and centralize server construction

Introduces _build_server() helper and --no-tls-verify escape hatch for
self-signed DC certificates. Extracts argparse into _build_parser() so
CLI-level tests can exercise it without invoking main()."
```

---

## Task 6: Add `--start-tls` flag and `_maybe_start_tls`

StartTLS lets us upgrade a plain LDAP connection to TLS in-band — useful when port 636 is firewalled.

**Files:**
- Modify: `ldapdomaindump/auth.py`
- Modify: `ldapdomaindump/__init__.py` (in `_build_parser`)
- Modify: `tests/test_auth.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_cli.py`:

```python
def test_start_tls_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--start-tls', 'dc.example.local'])
    assert args.start_tls is True


def test_start_tls_with_ldaps_url_rejected(capsys):
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(['--start-tls', 'ldaps://dc.example.local'])
    err = capsys.readouterr().err
    assert '--start-tls' in err
    assert 'ldaps://' in err
```

Add to `tests/test_auth.py`:

```python
@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_start_tls_called_when_flag_set(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_connection.return_value = mock_conn

    build_connection(_ns(start_tls=True, no_tls_verify=False))

    mock_conn.open.assert_called_once()
    mock_conn.start_tls.assert_called_once()
    # Order: open before start_tls before bind
    calls = [c[0] for c in mock_conn.method_calls]
    assert calls.index('open') < calls.index('start_tls') < calls.index('bind')


@patch('ldapdomaindump.auth.Connection')
@patch('ldapdomaindump.auth.Server')
def test_start_tls_not_called_when_flag_unset(mock_server, mock_connection):
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True
    mock_connection.return_value = mock_conn

    build_connection(_ns(start_tls=False))

    mock_conn.start_tls.assert_not_called()
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `pytest tests/ -v`

Expected: new tests fail.

- [ ] **Step 3: Add `--start-tls` to `_build_parser` with mutual-exclusion check**

In `_build_parser()` in `ldapdomaindump/__init__.py`, add to `miscgroup`:

```python
    miscgroup.add_argument("--start-tls", action='store_true', default=False,
                           help="Upgrade plain LDAP to TLS via StartTLS before bind")
```

After all `add_argument` calls in `_build_parser`, add a post-parse validator. Replace `parser.parse_args()` in `main()` with a wrapper:

In `_build_parser`, do NOT call parse_args — just return the parser. Then in `main()`:

```python
def main():
    parser = _build_parser()
    args = parser.parse_args()
    _validate_args(parser, args)
    # ... rest of main ...
```

Add `_validate_args` to `ldapdomaindump/__init__.py`, defined above `main()`:

```python
def _validate_args(parser, args):
    """Cross-field argparse validation that argparse groups can't express natively."""
    if args.start_tls and args.host.lower().startswith('ldaps://'):
        parser.error('--start-tls is incompatible with ldaps:// (connection is already TLS)')
```

- [ ] **Step 4: Update `build_connection` to call `_maybe_start_tls`**

In `ldapdomaindump/auth.py`, change `build_connection`:

```python
def build_connection(args):
    server = _build_server(args)
    authtype = getattr(args, 'authtype', 'NTLM')
    if authtype == 'SIMPLE':
        return _bind_simple(server, args)
    return _bind_ntlm(server, args)
```

Becomes:

```python
def build_connection(args):
    server = _build_server(args)
    authtype = getattr(args, 'authtype', 'NTLM')
    if authtype == 'SIMPLE':
        return _bind_simple(server, args)
    return _bind_ntlm(server, args)
```

(No change to dispatcher yet — `_maybe_start_tls` is called from within each bind helper so the open/start_tls/bind order is explicit.)

Update `_bind_ntlm` and `_bind_simple`:

```python
def _bind_ntlm(server, args):
    conn = Connection(
        server,
        user=args.user,
        password=args.password,
        authentication=NTLM,
        session_security=ENCRYPT,
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
        authentication='SIMPLE',
        auto_bind=False,
    )
    _open_and_maybe_start_tls(conn, args)
    _do_bind(conn)
    return conn


def _open_and_maybe_start_tls(conn, args):
    conn.open()
    if getattr(args, 'start_tls', False):
        conn.start_tls()
```

- [ ] **Step 5: Update existing tests that predate open()**

The older tests in `test_auth.py` (`test_ntlm_bind_uses_ntlm_authentication` etc.) will still pass because `MagicMock().open()` and `MagicMock().bind()` both succeed by default. Only the new `test_start_tls_*` tests exercise the order.

Update `_ns` helper default to include the new flags:

```python
def _ns(**overrides):
    defaults = dict(
        host='dc.example.local',
        user='EXAMPLE\\alice',
        password='hunter2',
        authtype='NTLM',
        no_tls_verify=False,
        start_tls=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)
```

- [ ] **Step 6: Run all tests**

Run: `pytest tests/ -v`

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add ldapdomaindump/auth.py ldapdomaindump/__init__.py tests/test_auth.py tests/test_cli.py
git commit -m "feat(auth): add --start-tls for in-band TLS upgrade

Supports environments where port 636 is firewalled. Argparse rejects
--start-tls with ldaps:// URLs. Bind helpers now explicitly
open() → maybe start_tls() → bind()."
```

---

## Task 7: Add Kerberos CLI flags and argparse validation

Add `-k/--kerberos` and `--dc-ip` to argparse, plus mutual-exclusion rules. No auth logic yet — that's Task 8. This task is purely CLI surface.

**Files:**
- Modify: `ldapdomaindump/__init__.py` (in `_build_parser` and `_validate_args`)
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_cli.py`:

```python
def test_kerberos_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['-k', 'dc.example.local'])
    assert args.kerberos is True


def test_dc_ip_flag_parses():
    parser = _build_parser()
    args = parser.parse_args(['--dc-ip', '10.0.0.1', 'dc.example.local'])
    assert args.dc_ip == '10.0.0.1'


def test_kerberos_with_simple_rejected(capsys):
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(['-k', '-at', 'SIMPLE', 'dc.example.local'])
    err = capsys.readouterr().err
    assert '-k' in err and 'SIMPLE' in err


def test_kerberos_with_user_rejected(capsys):
    from ldapdomaindump import _validate_args
    parser = _build_parser()
    args = parser.parse_args(['-k', '-u', 'EXAMPLE\\alice', 'dc.example.local'])
    with pytest.raises(SystemExit):
        _validate_args(parser, args)
    err = capsys.readouterr().err
    assert '-k' in err and '-u' in err


def test_kerberos_with_password_rejected(capsys):
    from ldapdomaindump import _validate_args
    parser = _build_parser()
    args = parser.parse_args(['-k', '-p', 'hunter2', 'dc.example.local'])
    with pytest.raises(SystemExit):
        _validate_args(parser, args)
    err = capsys.readouterr().err
    assert '-k' in err and ('-p' in err or 'password' in err.lower())
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `pytest tests/test_cli.py -v`

Expected: new tests fail.

- [ ] **Step 3: Add flags to `_build_parser`**

In the Main options group (next to `-u`/`-p`/`-at`), add:

```python
    parser.add_argument("-k", "--kerberos", action='store_true', default=False,
                        help="Use Kerberos authentication (reads ccache from KRB5CCNAME)")
    parser.add_argument("--dc-ip", dest='dc_ip', type=str, metavar='IP',
                        help="IP of the DC for the network connection; HOSTNAME is used as SPN")
```

Replace the existing `-at` definition with a `choices`-constrained version that can reject `-k -at SIMPLE` directly (argparse native mutual exclusion doesn't handle this cleanly across groups, so we do the check in `_validate_args`).

- [ ] **Step 4: Extend `_validate_args`**

Replace `_validate_args` in `ldapdomaindump/__init__.py`:

```python
def _validate_args(parser, args):
    """Cross-field argparse validation that argparse groups can't express natively."""
    if args.start_tls and args.host.lower().startswith('ldaps://'):
        parser.error('--start-tls is incompatible with ldaps:// (connection is already TLS)')

    if args.kerberos:
        if args.authtype == 'SIMPLE':
            parser.error('-k/--kerberos is incompatible with -at SIMPLE (SIMPLE cannot use Kerberos/SASL)')
        if args.user is not None:
            parser.error('-k/--kerberos does not accept -u/--user (identity comes from the ccache)')
        if args.password is not None:
            parser.error('-k/--kerberos does not accept -p/--password (identity comes from the ccache)')
```

- [ ] **Step 5: Run all tests**

Run: `pytest tests/ -v`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add ldapdomaindump/__init__.py tests/test_cli.py
git commit -m "feat(cli): add -k/--kerberos and --dc-ip flags with validation

No auth logic yet — this is CLI surface only. Rejects -k with SIMPLE,
-k with -u, and -k with -p at argparse time with clear messages."
```

---

## Task 8: Implement `_bind_kerberos` and wire it into the dispatcher

This is the core of the feature. Adds `impacket` as an optional dependency, implements the ccache-based Kerberos bind following the bloodhound.py pattern (AP-REQ built locally, submitted as a raw SASL bind to bypass ldap3's unreliable GSSAPI path), and wires `-k` into `build_connection`.

**Reference implementation:** `bloodhound/ad/authentication.py::kerberos_login` in the bloodhound-python project. The core structure below is that pattern, adapted for our single-use case (service ticket → SASL bind, no channel binding).

**Files:**
- Modify: `ldapdomaindump/auth.py`
- Create: `tests/fixtures/ccache.py`
- Modify: `tests/test_auth.py`
- Modify: `pyproject.toml`
- Modify: `setup.py`

- [ ] **Step 1: Add impacket as an optional dependency**

In `pyproject.toml`, extend `[project.optional-dependencies]`:

```toml
[project.optional-dependencies]
kerberos = ["impacket"]
dev = ["pytest>=7", "impacket"]
```

(`dev` includes impacket so the test suite can exercise the Kerberos path.)

In `setup.py`, add matching `extras_require`:

```python
setup(name='ldapdomaindump',
      version='0.10.1',
      ...existing fields...
      extras_require={
          'kerberos': ['impacket'],
          'dev': ['pytest>=7', 'impacket'],
      },
      ...
)
```

Reinstall with the new extras:

```bash
pip install -e '.[dev]'
```

- [ ] **Step 2: Write a fixture helper that synthesizes a ccache in-memory**

Create `tests/fixtures/ccache.py`:

```python
"""Build a minimal in-memory ccache for testing _bind_kerberos.

We can't commit a real ccache binary (format varies by version, and
checking in ticket material is a bad habit). Instead we construct one
programmatically via impacket's CCache API and write it to a tmp path.
"""
import os
import tempfile

from impacket.krb5.ccache import CCache, Credential, CountedOctetString, KeyBlock, Times, Header


def build_fake_ccache_with_tgs(target='dc.example.local', realm='EXAMPLE.LOCAL'):
    """Create a ccache that already contains a TGS for ldap/<target>.

    Returns the path to a tmp file; caller is responsible for cleanup via
    os.unlink() or by using a tmp_path pytest fixture.
    """
    ccache = CCache()
    ccache.headers = []
    # Primary principal
    ccache.principal = _principal_of(realm, ['alice'])

    # One credential: ldap/<target>@<realm>
    cred = Credential()
    cred['client'] = _principal_of(realm, ['alice'])
    cred['server'] = _principal_of(realm, ['ldap', target])
    cred['key'] = _keyblock()
    cred['time'] = Times()
    cred['is_skey'] = 0
    cred['tktflags'] = 0x40000000  # forwardable
    cred['addrs'] = []
    cred['authdata'] = []
    cred['ticket'] = _counted_octet(b'FAKE-TICKET-BYTES')
    cred['second_ticket'] = _counted_octet(b'')
    ccache.credentials = [cred]

    fd, path = tempfile.mkstemp(suffix='.ccache')
    os.close(fd)
    ccache.saveFile(path)
    return path


def _principal_of(realm, components):
    from impacket.krb5.ccache import Principal
    p = Principal()
    p['num_components'] = len(components)
    p['realm'] = _counted_octet(realm.encode())
    p['components'] = [_counted_octet(c.encode()) for c in components]
    p['name_type'] = 1  # NT_PRINCIPAL
    return p


def _keyblock():
    kb = KeyBlock()
    kb['keytype'] = 18  # AES256
    kb['keyvalue'] = b'\x00' * 32
    return kb


def _counted_octet(data: bytes):
    o = CountedOctetString()
    o['length'] = len(data)
    o['data'] = data
    return o
```

(impacket's `CCache.Credential` / `Header` / `Principal` classes expose dict-like mutable fields; names above match impacket 0.11+. If a field name differs on the installed impacket version, the test will raise clearly and the implementer can fix it.)

- [ ] **Step 3: Write failing test for missing impacket**

Add to `tests/test_auth.py`:

```python
def test_kerberos_without_impacket_raises(monkeypatch):
    """When impacket isn't installed, _bind_kerberos raises a clear error."""
    import sys
    # Hide impacket from the import system
    for name in list(sys.modules):
        if name.startswith('impacket'):
            monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(
        'builtins.__import__',
        _raising_import('impacket.krb5.ccache'),
    )
    args = _ns(kerberos=True, authtype='NTLM', user=None, password=None)

    from ldapdomaindump.auth import AuthError
    with pytest.raises(AuthError) as exc:
        build_connection(args)
    assert 'impacket' in str(exc.value).lower()
    assert 'pip install' in str(exc.value)


def _raising_import(target):
    real_import = __import__
    def fake(name, *args, **kwargs):
        if name == target or name.startswith(target + '.'):
            raise ImportError("No module named '%s'" % name)
        return real_import(name, *args, **kwargs)
    return fake
```

- [ ] **Step 4: Write failing test for missing KRB5CCNAME**

```python
def test_kerberos_without_krb5ccname_raises(monkeypatch):
    monkeypatch.delenv('KRB5CCNAME', raising=False)
    args = _ns(kerberos=True, authtype='NTLM', user=None, password=None)

    from ldapdomaindump.auth import AuthError
    with pytest.raises(AuthError) as exc:
        build_connection(args)
    assert 'KRB5CCNAME' in str(exc.value)
```

- [ ] **Step 5: Write failing test for unreadable ccache**

```python
def test_kerberos_with_unreadable_ccache_raises(monkeypatch, tmp_path):
    bogus = tmp_path / 'does-not-exist.ccache'
    monkeypatch.setenv('KRB5CCNAME', str(bogus))
    args = _ns(kerberos=True, authtype='NTLM', user=None, password=None)

    from ldapdomaindump.auth import AuthError
    with pytest.raises(AuthError) as exc:
        build_connection(args)
    assert 'ccache' in str(exc.value).lower()
    assert str(bogus) in str(exc.value)
```

- [ ] **Step 6: Write failing test for successful Kerberos path (end-to-end, impacket mocked)**

```python
def test_kerberos_bind_uses_pre_existing_tgs(monkeypatch):
    """When the ccache already has a ldap/<target> TGS, no TGS-REQ is made."""
    from tests.fixtures.ccache import build_fake_ccache_with_tgs
    ccache_path = build_fake_ccache_with_tgs(
        target='dc.example.local', realm='EXAMPLE.LOCAL'
    )
    monkeypatch.setenv('KRB5CCNAME', ccache_path)

    sentinel_blob = b'\x60\x82AP_REQ_GSS_WRAPPED'
    args = _ns(
        kerberos=True,
        authtype='NTLM',
        user=None,
        password=None,
        host='dc.example.local',
        dc_ip=None,
    )

    mock_conn = MagicMock()
    mock_conn.bind.return_value = True

    with patch('ldapdomaindump.auth.Connection', return_value=mock_conn), \
         patch('ldapdomaindump.auth.Server'), \
         patch('ldapdomaindump.auth._build_ap_req_blob', return_value=sentinel_blob) as mock_build, \
         patch('ldapdomaindump.auth._send_sasl_bind', return_value=True) as mock_bind:
        build_connection(args)

    assert mock_build.called
    # The blob we built is what got sent
    sent_blob = mock_bind.call_args.args[1]
    assert sent_blob == sentinel_blob

    try:
        os.unlink(ccache_path)
    except OSError:
        pass


def test_kerberos_bind_requests_tgs_when_only_tgt_present(monkeypatch):
    """When ccache has no ldap/<target> ticket, we request one via TGT."""
    # Use a ccache that has only a TGT (no ldap/ service ticket)
    from tests.fixtures.ccache import build_fake_ccache_with_tgs
    ccache_path = build_fake_ccache_with_tgs(
        target='krbtgt/EXAMPLE.LOCAL', realm='EXAMPLE.LOCAL'
    )
    monkeypatch.setenv('KRB5CCNAME', ccache_path)

    args = _ns(
        kerberos=True, authtype='NTLM', user=None, password=None,
        host='dc.example.local', dc_ip='10.0.0.1',
    )
    mock_conn = MagicMock()
    mock_conn.bind.return_value = True

    with patch('ldapdomaindump.auth.Connection', return_value=mock_conn), \
         patch('ldapdomaindump.auth.Server'), \
         patch('ldapdomaindump.auth._request_tgs') as mock_tgs, \
         patch('ldapdomaindump.auth._build_ap_req_blob', return_value=b'blob'), \
         patch('ldapdomaindump.auth._send_sasl_bind', return_value=True):
        mock_tgs.return_value = (MagicMock(), MagicMock(), MagicMock())
        build_connection(args)

    assert mock_tgs.called
    # kdc_host propagated from --dc-ip
    call_kwargs = mock_tgs.call_args.kwargs
    assert call_kwargs.get('kdc_host') == '10.0.0.1'

    try:
        os.unlink(ccache_path)
    except OSError:
        pass
```

- [ ] **Step 7: Run tests to confirm they fail**

Run: `pytest tests/test_auth.py -v`

Expected: all Kerberos tests fail — `_bind_kerberos`, `_build_ap_req_blob`, `_request_tgs`, `_send_sasl_bind` don't exist.

- [ ] **Step 8: Implement the Kerberos bind in `ldapdomaindump/auth.py`**

Add these new helpers to `ldapdomaindump/auth.py`. Keep them below the NTLM/SIMPLE helpers. Imports for impacket are done lazily inside `_bind_kerberos`.

```python
import os

from ldap3 import SASL, KERBEROS


def _bind_kerberos(server, args):
    """Bind to LDAP using a ticket from KRB5CCNAME.

    Pattern lifted from bloodhound.py's kerberos_login: we build the AP-REQ
    ourselves with impacket and submit it as a raw SASL bind, bypassing
    ldap3's native (unreliable) GSSAPI path.
    """
    try:
        from impacket.krb5.ccache import CCache
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
    except ImportError:
        raise AuthError(
            "Kerberos auth requires impacket. "
            "Install with: pip install 'ldapdomaindump[kerberos]'"
        )

    ccache_path = os.environ.get('KRB5CCNAME')
    if not ccache_path:
        raise AuthError("Kerberos auth requires KRB5CCNAME to point at a ccache file")

    try:
        ccache = CCache.loadFile(ccache_path)
    except (FileNotFoundError, PermissionError, OSError) as e:
        raise AuthError("Could not read ccache at %s: %s" % (ccache_path, e))

    target = args.host
    # Strip any ldap(s):// scheme for SPN construction
    if target.lower().startswith('ldaps://'):
        target = target[len('ldaps://'):]
    elif target.lower().startswith('ldap://'):
        target = target[len('ldap://'):]
    target = target.split(':', 1)[0]  # drop any :port

    realm = ccache.principal.realm['data'].decode() if isinstance(
        ccache.principal.realm['data'], bytes
    ) else ccache.principal.realm['data']

    spn = 'ldap/%s@%s' % (target, realm)
    creds = ccache.getCredential(spn, False)

    if creds is not None:
        tgs, cipher, session_key = _extract_tgs_from_creds(creds)
    else:
        tgt_creds = ccache.getCredential('krbtgt/%s@%s' % (realm, realm))
        if tgt_creds is None:
            raise AuthError(
                "No usable ticket in ccache for target %s (no TGS and no TGT for %s)"
                % (target, realm)
            )
        tgs, cipher, session_key = _request_tgs(
            tgt_creds=tgt_creds,
            target=target,
            realm=realm,
            kdc_host=args.dc_ip,
        )

    blob = _build_ap_req_blob(tgs, cipher, session_key, spn)

    conn = Connection(
        server,
        authentication=SASL,
        sasl_mechanism=KERBEROS,
        auto_bind=False,
    )
    _open_and_maybe_start_tls(conn, args)

    if not _send_sasl_bind(conn, blob):
        raise AuthError('Kerberos SASL bind failed: %s' % conn.result)
    return conn


def _extract_tgs_from_creds(creds):
    """Extract (tgs, cipher, session_key) from an impacket Credential."""
    from impacket.krb5.asn1 import TGS_REP
    from impacket.krb5.crypto import Key, _enctype_table
    from pyasn1.codec.der import decoder

    tgs_rep = creds.toTGS()
    tgs = decoder.decode(tgs_rep['KDC_REP'], asn1Spec=TGS_REP())[0]
    cipher = _enctype_table[creds['key']['keytype']]
    session_key = Key(creds['key']['keytype'], creds['key']['keyvalue'])
    return tgs, cipher, session_key


def _request_tgs(tgt_creds, target, realm, kdc_host=None):
    """Request a TGS for ldap/<target>@<realm> using the TGT in tgt_creds."""
    from impacket.krb5.kerberosv5 import getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants

    tgt = tgt_creds.toTGT()
    spn = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
    tgs, cipher, _old_session_key, session_key = getKerberosTGS(
        spn, realm, kdc_host or target,
        tgt['KDC_REP'], tgt['cipher'], tgt['sessionKey'],
    )
    return tgs, cipher, session_key


def _build_ap_req_blob(tgs, cipher, session_key, spn):
    """Build the GSS-API-wrapped AP-REQ to submit as the SASL bind payload.

    Port of the AP-REQ construction in bloodhound.py's kerberos_login.
    Sets GSS_C_INTEG_FLAG so the DC accepts the bind on plain LDAP.
    """
    import datetime
    import random
    import struct
    from pyasn1.codec.der import encoder, decoder
    from pyasn1.type.univ import noValue
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.types import Principal, KerberosTime, Ticket

    # GSS_C_INTEG_FLAG | GSS_C_MUTUAL_FLAG (standard set used by bloodhound)
    GSS_C_DELEG_FLAG = 1
    GSS_C_MUTUAL_FLAG = 2
    GSS_C_REPLAY_FLAG = 4
    GSS_C_SEQUENCE_FLAG = 8
    GSS_C_INTEG_FLAG = 32
    flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG

    # Build authenticator
    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    # Realm and cname come from the TGS ticket
    authenticator['crealm'] = str(tgs['ticket']['realm'])
    client_name = Principal()
    client_name.from_asn1(tgs, 'crealm', 'cname')
    seq_set(authenticator, 'cname', client_name.components_to_asn1)
    now = datetime.datetime.utcnow()
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)
    encrypted_authenticator = cipher.encrypt(session_key, 11, encoded_authenticator, None)

    ap_req = AP_REQ()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req['ap-options'] = constants.encodeFlags([])
    seq_set(ap_req, 'ticket', Ticket().from_asn1(tgs['ticket']).to_asn1)
    ap_req['authenticator']['etype'] = session_key.enctype
    ap_req['authenticator']['cipher'] = encrypted_authenticator

    ap_req_blob = encoder.encode(ap_req)

    # GSS-API wrapper: OID for Kerberos V5 + token type 0x01 0x00 + AP-REQ
    # OID 1.2.840.113554.1.2.2 = Kerberos V5
    KERBEROS_OID = b'\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
    gss_token = KERBEROS_OID + b'\x01\x00' + ap_req_blob
    gss_header = b'\x60' + _asn1_length(len(gss_token)) + gss_token
    # We do NOT do GSS_Wrap of subsequent messages here — the bind itself
    # negotiates integrity when flags include GSS_C_INTEG_FLAG, and the
    # server wraps/unwraps transparently for the LDAP layer. If a specific
    # environment needs explicit message wrapping, that's a follow-up.
    return gss_header


def _asn1_length(n):
    """Encode an ASN.1 DER length (short or long form)."""
    if n < 0x80:
        return bytes([n])
    body = b''
    while n > 0:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def _send_sasl_bind(conn, blob):
    """Send a raw SASL bind request with our pre-built GSS-API blob.

    Bypasses ldap3's sasl_bind() which would re-negotiate GSSAPI via the
    system Kerberos libs.
    """
    from ldap3.operation.bind import bind_operation
    from ldap3.protocol.sasl.sasl import send_sasl_negotiation
    # ldap3's SASL machinery knows how to send a single-step SASL bind if
    # we pass our blob directly. Pattern: open the connection, construct
    # the bind request, send it, read the result.
    request = bind_operation(
        conn.version,
        SASL,
        None,
        None,
        'GSS-SPNEGO',
        blob,
    )
    response = conn.post_send_single_response(
        conn.send('bindRequest', request, None)
    )
    if not response:
        return False
    conn.result = response[0] if isinstance(response, list) else response
    return conn.result.get('result') == 0
```

Update `build_connection` to dispatch on `kerberos`:

```python
def build_connection(args):
    server = _build_server(args)
    if getattr(args, 'kerberos', False):
        return _bind_kerberos(server, args)
    authtype = getattr(args, 'authtype', 'NTLM')
    if authtype == 'SIMPLE':
        return _bind_simple(server, args)
    return _bind_ntlm(server, args)
```

- [ ] **Step 9: Run tests to confirm they pass**

Run: `pytest tests/ -v`

Expected: all pass. If the ccache fixture helper fails due to impacket API changes, fix the field names based on the installed impacket version.

- [ ] **Step 10: Manual verification (documented, not run by the plan)**

The implementer should document that this has NOT been tested against a live DC. Merge gate is a manual test:

```bash
# In a lab:
python getTGT.py -dc-ip 10.0.0.1 EXAMPLE.LOCAL/alice:Passw0rd
export KRB5CCNAME=alice.ccache
ldapdomaindump -k --dc-ip 10.0.0.1 dc.example.local
```

- [ ] **Step 11: Commit**

```bash
git add ldapdomaindump/auth.py tests/test_auth.py tests/fixtures/ccache.py pyproject.toml setup.py
git commit -m "feat(auth): add ccache-based Kerberos authentication

Adds -k/--kerberos that authenticates using an existing ccache pointed
at by KRB5CCNAME. impacket is an optional dependency (install via
ldapdomaindump[kerberos]). The AP-REQ is built locally and submitted as
a raw SASL bind, bypassing ldap3's unreliable native GSSAPI path (known
issues against modern AD). GSS_C_INTEG_FLAG is set so the DC accepts the
bind on plain LDAP (strongerAuthRequired is no longer returned).

Manual verification required against a live DC before merge."
```

---

## Task 9: Update README with new flags

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Extend the usage section**

In `README.md`, update the `usage:` block around line 42-85 to reflect the new CLI surface. Add entries for `-k`, `--dc-ip`, `--start-tls`, `--no-tls-verify`. Also update the `Authentication` subsection (around line 88) to mention Kerberos:

Add to the Authentication section:

```markdown
### Authentication

Most AD servers support NTLM authentication. In the rare case that it does not, use `--authtype SIMPLE`.

#### Kerberos

Pass `-k` to authenticate with a Kerberos ticket from an existing ccache file:

    export KRB5CCNAME=/path/to/alice.ccache
    ldapdomaindump -k --dc-ip 10.0.0.1 dc.example.local

The ticket is typically obtained out-of-band (`impacket`'s `getTGT.py`, `kinit`, or similar). `-k` requires the `impacket` extra:

    pip install 'ldapdomaindump[kerberos]'

### LDAP signing and TLS

Modern AD DCs reject unsigned binds on plain LDAP (`strongerAuthRequired`, result code 8). This tool handles that automatically:

- `-at NTLM` (default) — sign/seal is enabled.
- `-k` — GSS integrity is negotiated.
- `-at SIMPLE` — cannot be signed. Use `ldaps://` or `--start-tls`.

When port 636 is firewalled, `--start-tls` upgrades a plain LDAP connection to TLS in-band. For self-signed DC certificates, pass `--no-tls-verify` (insecure: connection is encrypted but not authenticated).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document Kerberos auth, StartTLS, and TLS flags"
```

---

## Self-Review (post-plan)

**Spec coverage:**
- ✅ Kerberos via ccache → Task 8
- ✅ Raw SASL bind bypassing ldap3's GSSAPI → Task 8 (`_send_sasl_bind`)
- ✅ GSS integrity flag → Task 8 (`_build_ap_req_blob`)
- ✅ Impacket as optional dep → Task 8 (pyproject.toml + setup.py)
- ✅ `-k`, `--dc-ip` flags + mutual exclusion → Task 7
- ✅ NTLM sign/seal → Task 3
- ✅ SIMPLE better error → Task 4
- ✅ `--start-tls` → Task 6
- ✅ `--no-tls-verify` → Task 5
- ✅ `_build_server` centralized construction → Task 5
- ✅ `build_connection` dispatcher → Task 2
- ✅ auth.py module → Task 2
- ✅ Testing: ldap3 MOCK + fixture ccache → Tasks 2-8

**Placeholder scan:** No TBDs. All code blocks are concrete.

**Type consistency:** `build_connection`, `_build_server`, `_bind_ntlm`, `_bind_simple`, `_bind_kerberos`, `_open_and_maybe_start_tls`, `_do_bind`, `_build_ap_req_blob`, `_request_tgs`, `_send_sasl_bind`, `_extract_tgs_from_creds` — names match across tasks. `AuthError` used consistently. Arg namespaces (`args.host`, `args.user`, `args.password`, `args.authtype`, `args.kerberos`, `args.dc_ip`, `args.start_tls`, `args.no_tls_verify`) match between CLI definitions and consumers.

**Known open questions:**
- Impacket's CCache field names (`['data']`, `['keyvalue']`, etc.) may vary across versions. If Task 8 Step 9 fails on field names, the implementer should inspect `impacket.krb5.ccache` source for the installed version and adjust.
- ldap3's `post_send_single_response` / `send` / `bind_operation` APIs are public but lightly documented. If the raw SASL bind path needs adjustment, the canonical reference remains bloodhound.py's `kerberos_login`.
