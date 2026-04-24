# Kerberos Authentication Support — Design

**Status:** Approved (pending spec review)
**Date:** 2026-04-23
**Branch:** `feature/kerberos-auth`

## Summary

Add Kerberos authentication to `ldapdomaindump` using an existing impacket-style ccache file (pointed at by `KRB5CCNAME`). Because ldap3's native SASL/GSSAPI path is known to be unreliable against Active Directory, the implementation builds the AP-REQ with impacket and feeds it as a raw SASL bind — the pattern used by `bloodhound.py` and `krbrelayx`.

As part of the same refactor, resolve the `strongerAuthRequired` (LDAP error 8) failure that hardened AD DCs return for unsigned binds on plain LDAP, and add StartTLS support for environments where port 636 (LDAPS) is unreachable.

## Goals

- Support Kerberos authentication to LDAP via a pre-existing ccache file.
- Work on modern, hardened AD DCs that require signing/sealing on plain LDAP.
- Work in environments where port 636 is firewalled but plain 389 with StartTLS is reachable.
- Leave the existing NTLM and SIMPLE auth flows behaviorally unchanged.
- Isolate all authentication logic into one module with a clean, dispatch-driven interface.

## Non-Goals

- Password-to-Kerberos (requesting a TGT ourselves from a username/password or hash). Ccache-only; users obtain their ticket out-of-band via `getTGT.py` / `kinit` / etc.
- Replacing `ldap3` with a different LDAP library.
- Auto-upgrading `ldap://` to `ldaps://` transparently. Silent changes to the security posture are out of scope.
- Kerberos channel binding (LDAP signing addresses the same class of hardening and is simpler; channel binding is a possible follow-up).
- **NTLM sign/seal.** ldap3 2.9.1 does not support `session_security=ENCRYPT` — no `ENCRYPT` constant, no `session_security` kwarg, no NTLM sealing in the library. Implementing it would require either a library swap or extensive monkey-patching, both out of scope. Users who hit `strongerAuthRequired` with NTLM have three working alternatives after this PR: LDAPS, `--start-tls`, or `-k` (Kerberos with GSS integrity).

## Architecture

### New module: `ldapdomaindump/auth.py`

All authentication concerns move here behind one public function:

```python
def build_connection(args) -> ldap3.Connection
```

`main()` in `ldapdomaindump/__init__.py` stops doing auth directly; it parses args, calls `build_connection(args)`, and hands the bound `Connection` to `domainDumper`.

Internal helpers (all private):

- `_build_server(args) -> ldap3.Server` — constructs the `Server` with the right `use_ssl` / `Tls` settings based on the URL scheme and `--no-tls-verify`.
- `_maybe_start_tls(connection, args)` — calls `connection.start_tls()` when `--start-tls` is set, after `open()` but before the bind.
- `_bind_ntlm(server, args) -> ldap3.Connection` — current NTLM path, plus `session_security=ldap3.ENCRYPT` to enable NTLM sign/seal on plain LDAP.
- `_bind_simple(server, args) -> ldap3.Connection` — current SIMPLE path, verbatim. On `strongerAuthRequired`, emits a clearer error pointing the user at `-at NTLM`, `-k`, `ldaps://`, or `--start-tls`.
- `_bind_kerberos(server, args) -> ldap3.Connection` — the new path.

### Kerberos bind (`_bind_kerberos`)

Follows the `bloodhound.py` / `krbrelayx` pattern:

1. Lazy-import impacket modules. If import fails, raise with a clear install hint.
2. Resolve the ccache path from `os.environ['KRB5CCNAME']`. Fail fast if unset or unreadable.
3. Load the ccache with `impacket.krb5.ccache.CCache.loadFile()`.
4. Look for a pre-existing service ticket for `ldap/<target_fqdn>`. If absent, pull the TGT and request a TGS via impacket's `getKerberosTGS`, using `--dc-ip` (if supplied) as the KDC host, otherwise the target.
5. Build the AP-REQ with the GSS-API integrity flag (`GSS_C_INTEG_FLAG`) set.
6. Wrap it in the GSS-API OID blob and submit it as a raw SASL bind to the `ldap3.Connection`, bypassing ldap3's native GSSAPI SASL code path entirely. This is the part that works around the known ldap3 issues.
7. After the bind, outgoing LDAP messages are GSS-wrapped to satisfy the DC's signing requirement on plain LDAP. When the transport is already TLS (LDAPS or StartTLS), wrapping is a no-op and skipped.

Impacket becomes an **optional** dependency. It's listed in `pyproject.toml` as an `[project.optional-dependencies]` extra (`kerberos`), and the import happens only inside `_bind_kerberos`. Users who never touch `-k` don't need it installed.

## CLI Surface

New flags on `main()`'s argparse:

| Flag | Behavior |
|---|---|
| `-k`, `--kerberos` | Enable Kerberos auth. Reads ccache from `KRB5CCNAME`. |
| `--dc-ip` | IP address of the DC for the network connection. The positional `HOSTNAME` is used for the SPN. |
| `--start-tls` | Call `start_tls()` after open, before bind. |
| `--no-tls-verify` | Disable TLS certificate validation. Emits a loud warning. |

Mutually-exclusive / invalid combinations (rejected at argparse time via `parser.error`):

- `-k` with `-at SIMPLE` (SIMPLE does not support Kerberos/SASL).
- `-k` with `-u` or `-p` (identity comes from the ccache — accepting username/password on the CLI would be misleading).
- `--start-tls` with an `ldaps://` URL (connection is already TLS).

When `-k` is set, no `-u` is required; the principal is read from the ccache.

## Data Flow

```
main()
  └─ parse args
  └─ build_connection(args)                          # auth.py
       ├─ server = _build_server(args)               # handles scheme + Tls
       ├─ connection = Connection(server, ..., auto_bind=False)
       ├─ connection.open()
       ├─ _maybe_start_tls(connection, args)
       └─ dispatch:
            ├─ args.kerberos              → _bind_kerberos(server, args)
            │    ├─ CCache.loadFile(os.environ['KRB5CCNAME'])
            │    ├─ pick TGS for ldap/<target> or request it via TGT
            │    ├─ build AP-REQ with GSS_C_INTEG_FLAG
            │    └─ raw SASL bind (bypass ldap3 native GSSAPI)
            ├─ args.authtype == 'NTLM'    → _bind_ntlm(server, args)
            │    └─ Connection(..., authentication=NTLM, session_security=ENCRYPT)
            └─ args.authtype == 'SIMPLE'  → _bind_simple(server, args)
                 └─ Connection(..., authentication=SIMPLE)
  └─ domainDumper(server, connection, cnf).domainDump()
```

## LDAP Signing / Integrity

The `strongerAuthRequired` (LDAP result code 8) error is thrown by hardened AD DCs against unsigned binds on plain LDAP. The situation per auth type:

- **Kerberos** — include `GSS_C_INTEG_FLAG` in the AP-REQ and wrap outgoing LDAP messages with `GSS_Wrap` when the transport is plain. Skipped when transport is TLS.
- **NTLM** — ldap3 2.9.1 does not support signing. NTLM on plain LDAP will continue to fail against hardened DCs. On `strongerAuthRequired`, we surface:

  > `NTLM bind rejected: server requires signing, and the installed ldap3 does not support NTLM sign/seal. Use -k (Kerberos), or use ldaps://<host> if reachable, or pass --start-tls.`

- **SIMPLE** — cannot be signed. On `strongerAuthRequired`, we surface:

  > `SIMPLE bind rejected: server requires signing, and SIMPLE binds cannot negotiate signing. Use -k (Kerberos, which signs over plain LDAP), or use ldaps://<host> if reachable, or pass --start-tls.`

## StartTLS

When port 636 is firewalled but the DC answers on 389 with a TLS-capable extended operation, StartTLS lets us upgrade the plain connection in-band and then bind normally (including SIMPLE, which works fine over encrypted transport).

Implementation: `connection.start_tls()` after `open()`. Certificate validation is on by default (ldap3's default `Tls()` validates against the system CA store). `--no-tls-verify` builds `Tls(validate=ssl.CERT_NONE)` and prints:

> `[!] TLS certificate validation disabled. Connection is encrypted but not authenticated.`

## Error Handling

All failures raise exceptions from `build_connection`; `main()` catches them, logs via `log_warn`, and `sys.exit(1)`. Specific cases and messages:

| Failure | Message |
|---|---|
| `-k` passed but impacket not installed | `Kerberos auth requires impacket. Install with: pip install 'ldapdomaindump[kerberos]'` |
| `-k` passed but `KRB5CCNAME` unset | `Kerberos auth requires KRB5CCNAME to point at a ccache file` |
| ccache file missing / unreadable | `Could not read ccache at <path>: <os error>` |
| ccache has no usable ticket for target | `No usable ticket in ccache for target <host>` |
| TGS-REQ fails (expired TGT, wrong realm, KDC unreachable) | Surface impacket's `KerberosError` message verbatim |
| LDAP bind returns `strongerAuthRequired` (SIMPLE) | Specific message from the LDAP Signing section above |
| LDAP bind returns any other non-success | Print `c.result` (matches current behavior) |
| TLS handshake fails (untrusted cert) | Surface ldap3's `LDAPSocketOpenError` and suggest `--no-tls-verify` if appropriate |
| Invalid flag combinations | `argparse` `parser.error(...)` with a one-line explanation |

No silent fallbacks. If `-k` is requested and anything goes wrong, the tool stops.

## Testing

The repo has no existing test suite. We introduce `tests/` with a minimal setup matched to the scope of this change:

- **`tests/test_auth.py`**
  - **Argparse validation** — every mutually-exclusive combination listed in the CLI Surface section produces `SystemExit` with a non-empty `stderr`. Pure, no network.
  - **`_bind_ntlm` / `_bind_simple`** — driven against `ldap3`'s `MOCK_SYNC` strategy. Verify the resulting `Connection` has the expected `authentication` and (for NTLM) `session_security` values. Confirms the refactor didn't change observable behavior.
  - **`_bind_kerberos`**
    - Fixture: a tiny, hand-crafted ccache file committed under `tests/fixtures/test.ccache` containing a dummy TGS for `ldap/dc.example.local`.
    - impacket's `getKerberosTGS` is mocked out — we're testing our glue code, not impacket's network paths.
    - Assert that the AP-REQ we construct has `GSS_C_INTEG_FLAG` set, that the GSS-API OID wrapper is correctly formed, and that the SASL bind payload matches the expected blob.
  - **Error paths** — missing `KRB5CCNAME`, unreadable ccache, no ticket for target. Each asserts the specific error message.
- **Manual verification** (documented, not automated):
  1. `python getTGT.py -dc-ip <ip> LAB.LOCAL/user:password`
  2. `export KRB5CCNAME=user.ccache`
  3. `ldapdomaindump -k --dc-ip <ip> dc.lab.local`
  4. Confirm domain dump succeeds end-to-end.
  Repeat with `--start-tls` and with `ldaps://` URLs to cover the transport matrix.

Manual verification is the final gate before merge because no public AD test infrastructure exists.

## Dependencies

`pyproject.toml` gains:

```toml
[project.optional-dependencies]
kerberos = ["impacket"]
```

No changes to the required dependency list. Users who never pass `-k` pay nothing.

## Out of Scope (Follow-ups)

- Password/hash-to-Kerberos (we request the TGT ourselves).
- Kerberos channel binding on LDAPS (LDAP signing covers the same hardening surface; channel binding is a separate feature).
- Replacing ldap3. Today's pain is Kerberos-specific; a wholesale swap is a much larger decision with broader blast radius.
