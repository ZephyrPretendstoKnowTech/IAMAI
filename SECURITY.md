# Security

IAMAI reads live identity data from Microsoft Entra tenants, so its own security
posture matters. This document describes what it does and does not do, how it
handles data and credentials, and how to report a problem.

## Reporting a vulnerability

Please report security issues **privately**. On this repository, use GitHub's
"Report a vulnerability" under the Security tab (Security advisories), not a
public issue or pull request. Include what you found, how to reproduce it, and
the impact you see. You will get an acknowledgement, and a fix or an explanation.

Please do not include real tenant data, real user names, or secrets in a report.
A sanitized snapshot (`iamai sanitize`) is safe to attach if you need to show
data-shaped behaviour.

## The security model

- **Read only.** Every Graph permission the collector uses is a read permission.
  It cannot create, edit or delete a policy, an account or a setting. Setup asks
  for one write permission, `Application.ReadWrite.OwnedBy`, used only to create
  the tool's own collector app; it cannot touch any other application, and the
  broader "read-write everything" and "grant permissions" scopes are
  deliberately never requested.
- **Local.** No telemetry, no accounts, no uploads. The only network traffic is
  to Microsoft's own Graph and login endpoints. Everything collected stays in a
  folder on the machine that ran it.
- **Nothing is performed automatically.** The remediation plan is a document a
  person carries out by hand. The tool never changes a tenant.

## Data on disk

A collect writes a full, **unsanitized** copy of real identity data: user
principal names, display names, sign-in history, and until sanitized, IP and
location data, plus the real tenant id.

- `data/`, `certs/`, `config.yaml` and `baselines/` are git-ignored and must
  never be committed.
- Only a copy produced by `iamai sanitize` is safe to move off the machine. It
  replaces every real name, sign-in name, IP address and tenant id with a stable
  stand-in.
- Nothing is deleted on its own. `iamai purge <alias> --all` removes everything
  collected for a tenant, including the pseudonym map; `--keep-latest` and
  `--older-than` prune older snapshots.

## The credential

- Setup generates a self-signed certificate, valid for **180 days** by design,
  and stores it under `certs/`. On non-Windows systems the private key file is
  restricted to the owner. It is the single credential the tool uses to read
  every configured tenant, so treat the `certs/` folder accordingly.
- When the certificate nears expiry the tool warns; once expired it stops with a
  plain instruction to run `setup` again.
- Running `setup` on a second machine replaces the certificate and stops the
  first machine from authenticating until it is re-run there.

## The questionnaire server

`iamai wizard` serves a local page while you answer questions. It binds to
`127.0.0.1` only, refuses any request whose Host header is not a loopback name
(closing DNS-rebinding), and protects its one form-submitting route with a
per-run token. It sets no cookie and no session, and loads no external asset.

## Supply chain

Dependencies are installed with `--require-hashes` against a locked, hashed
`requirements.txt`, so every direct and transitive package is verified against a
recorded hash rather than whatever an index serves on the day. GitHub Actions,
if used, should be pinned by commit SHA.

## Scope

In scope: the IAMAI code in this repository and the artifacts it produces. Out of
scope: Microsoft Graph, Entra, and the tenant's own configuration, which the tool
only reads and reports on.
