"""IAMAI command line interface.

Commands are idempotent and file based. All user-facing text is plain
language for a reader with no IAM experience: numbered single-action steps,
no jargon without a one-line explanation.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import httpx
import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from iamai.config import Config, load_config, save_config
from iamai.graphclient import GraphClient, GraphError

# pretty_exceptions_show_locals=False: Typer's rich tracebacks render frame
# locals by default, and the setup helpers raise inside a scope holding the
# live device-code bearer token, so an unhandled Graph error would print that
# token (and a private-key PEM on a cert-load failure) straight past redact()
# (SECRETS-2-002).
app = typer.Typer(
    add_completion=False,
    pretty_exceptions_show_locals=False,
    help="Reads a Microsoft Entra tenant's identity security posture.",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"iamai {TOOL_VERSION}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Print the installed version and exit.",
    ),
) -> None:
    """Reads a Microsoft Entra tenant's identity security posture."""

def CERT_PEM() -> Path:
    from iamai.paths import cert_dir
    return cert_dir() / "iamai.pem"


def CERT_PUBLIC_PEM() -> Path:
    from iamai.paths import cert_dir
    return cert_dir() / "iamai-cert.pem"


CONSENT_URL_TEMPLATE = "https://login.microsoftonline.com/{tenantId}/adminconsent?client_id={appId}"

# The bootstrapper public client used for one-time setup device code flow.
# Register once: Entra > App registrations > New registration, name "IAMAI Setup",
# supported accounts "any organizational directory (multitenant)", no redirect URI.
# Authentication tab > Allow public client flows: Yes. No permissions in manifest.
# Paste the resulting Application (client) ID here.
SETUP_CLIENT_ID = ""  # populate before first run

# Microsoft Graph first-party app ID (universal constant, same in every tenant).
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

# Global Administrator role template ID (universal constant, same in every tenant).
GA_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

GRAPH_BASE = "https://graph.microsoft.com"
LOGIN_BASE = "https://login.microsoftonline.com"

# The Collector certificate is a standing credential that authenticates,
# headless, to every configured tenant, so its lifetime is the window a stolen
# copy stays useful. Kept deliberately short: a posture read is periodic, not
# continuous, so re-running setup twice a year is a small cost for halving the
# exposure window against the old two-year default.
CERT_LIFETIME_DAYS = 180

# Permission manifest from SPEC section 3. Application permissions, Microsoft Graph.
PERMISSION_TABLE: list[tuple[str, str]] = [
    ("Policy.Read.All", "CAPs, auth methods policy, registration campaign, security defaults, authorization policy, auth strengths"),
    ("Directory.Read.All", "Users, groups, membership resolution, org metadata"),
    ("AuditLog.Read.All", "Sign-in logs (interactive + non-interactive), signInActivity on users"),
    ("UserAuthenticationMethod.Read.All", "Registered methods per user"),
    ("Reports.Read.All", "userRegistrationDetails (MFA capability, the lockout predictor)"),
    ("Organization.Read.All", "subscribedSkus for license gating"),
    ("Domain.Read.All", "Managed vs federated domains"),
    ("RoleManagement.Read.Directory", "Role assignments, PIM eligible vs active"),
    ("Application.Read.All", "Service principals (SP preflight), app credentials, OAuth grants"),
    ("IdentityRiskyUser.Read.All", "Risky users, collected only when P2 detected, else skipped gracefully"),
]
PERMISSION_NAMES = [p for p, _ in PERMISSION_TABLE]


# How many days before expiry to start warning, so a re-run of setup happens
# on the operator's schedule rather than mid-collection against a live tenant.
CERT_RENEW_WARNING_DAYS = 21


def _check_cert_freshness(cert_path: Path) -> None:
    """Warn as the Collector certificate nears expiry, and stop with a clear
    instruction once it has expired, rather than letting a lapsed credential
    surface as an opaque authentication failure deep in a collect. The
    certificate is deliberately short lived (CERT_LIFETIME_DAYS), so this is
    the "then require a re-auth" half of that decision.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        not_after = cert.not_valid_after_utc
    except (OSError, ValueError):
        # A missing or unreadable cert is not this function's error to report;
        # the auth attempt that follows will surface its own clear failure.
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    if now >= not_after:
        typer.echo(
            f"The Collector certificate expired on {not_after.date()}. Run "
            "'iamai setup' to generate a new one and re-consent, then try again.",
            err=True,
        )
        raise typer.Exit(code=1)
    days_left = (not_after - now).days
    if days_left <= CERT_RENEW_WARNING_DAYS:
        typer.echo(
            f"The Collector certificate expires in {days_left} day(s), on "
            f"{not_after.date()}. Run 'iamai setup' before then to renew it.",
            err=True,
        )


_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _require_guid(value: str, what: str) -> str:
    """Accept only a GUID. Tenant and application IDs are GUIDs; enforcing that
    catches an operator typo and keeps a non-GUID (e.g. a newline-bearing
    value) out of the hand-rolled config.yaml writer (INJECT-2-001)."""
    value = (value or "").strip()
    if not _GUID_RE.match(value):
        typer.echo(f"'{value}' is not a valid {what} (expected a GUID).", err=True)
        raise typer.Exit(code=1)
    return value


def make_client(config: Config, tenant_id: str) -> GraphClient:
    """Build a Graph client from config. Tests replace this function."""
    _check_cert_freshness(Path(config.certPath))
    return GraphClient(
        tenant_id=tenant_id,
        app_id=config.appId,
        cert_path=Path(config.certPath),
    )


def _restrict_to_current_user_windows(path: Path) -> None:
    """Best-effort ACL restriction on Windows. On a repo that does not live
    under a user profile (e.g. C:\\iamai), inherited drive-root ACLs grant
    BUILTIN\\Users read, so on Windows icacls is the actual control for the
    private key, not mere defense in depth. It still must never fail the run,
    but a silent failure used to leave the key exposed with no signal
    (SECRETS-2-001, DEPLOY-2-003): warn instead."""
    user = os.environ.get("USERNAME")
    if not user:
        typer.echo(
            f"Could not restrict permissions on {path}: USERNAME is unset. "
            "Restrict it to your account by hand.",
            err=True,
        )
        return
    try:
        result = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            typer.echo(
                f"Could not restrict permissions on {path} (icacls exit "
                f"{result.returncode}). Restrict it to your account by hand.",
                err=True,
            )
    except (OSError, subprocess.SubprocessError) as exc:
        typer.echo(
            f"Could not restrict permissions on {path}: {exc}. Restrict it to "
            "your account by hand.",
            err=True,
        )


def _harden_key_file(cert_path: Path) -> None:
    """Restrict the private-key file to the current user. Applied whenever
    setup runs, not only when it generates a fresh key: a key created before
    this hardening existed, or copied in, would otherwise stay world-readable
    forever because setup keeps an existing cert untouched (SECRETS-2-001)."""
    try:
        if os.name != "nt":
            os.chmod(cert_path, 0o600)
        else:
            _restrict_to_current_user_windows(cert_path)
    except OSError as exc:
        typer.echo(
            f"Could not restrict permissions on {cert_path}: {exc}. Restrict "
            "it to your account by hand.",
            err=True,
        )


def generate_certificate(cert_path: Path, public_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IAMAI Collector")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_LIFETIME_DAYS))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    # This file holds the unencrypted private key, the sole credential this
    # tool uses to authenticate to every configured tenant. write_bytes()
    # creates the file with the process's default umask, which is
    # world-readable (0644) on a stock POSIX system -- any other local
    # account on a shared machine could read it. Opening with an explicit
    # restrictive mode closes that window rather than chmod-ing after the
    # fact, which would briefly leave the file at the default permissions
    # (KEY-001).
    fd = os.open(cert_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem + cert_pem)
    _harden_key_file(cert_path)
    # The public certificate is meant to be uploaded to the Entra app
    # registration; it carries no secret and is fine to leave readable.
    public_path.write_bytes(cert_pem)


# ---------------------------------------------------------------------------
# Setup helpers: device code flow + Graph write operations
# ---------------------------------------------------------------------------

# OwnedBy, not All: this lets setup create the Collector app and its service
# principal and manage only that app, never rewrite any other app in the
# tenant (verified against Microsoft Graph permissions reference,
# ASSUMPTIONS.md note 35). AppRoleAssignment.ReadWrite.All is deliberately NOT
# requested: it is the only scope that grants app roles and Microsoft warns it
# lets an app grant privileges to itself, so instead of granting consent
# programmatically, setup prints the admin-consent URL for the signed-in
# Global Administrator to approve read-only access through Microsoft's own
# screen -- the same flow already used for a second tenant.
SETUP_SCOPES = [f"{GRAPH_BASE}/Application.ReadWrite.OwnedBy"]

# Action segments that would make a Graph permission more than a read. A
# permission is Resource.Action.Scope (RoleManagement.Read.Directory), so the
# check works on whole dotted segments: the resource name may legitimately
# contain words like Management, but no segment may BE a write action. The
# read-only permission set is the product's main promise, so it is enforced
# here mechanically (setup refuses to request an offending set) and by test,
# not by convention (work order 2026-08-17, part 2.2).
_WRITE_ACTIONS = {
    "write", "readwrite", "create", "update", "delete", "manage",
    "fullcontrol", "accessasuser", "send", "invite",
}


def assert_permissions_read_only(names: list[str]) -> None:
    """Refuse any permission whose dotted segments are not plainly a read."""
    offenders = []
    for name in names:
        segments = [s.lower() for s in name.split(".")]
        if "read" not in segments or any(s in _WRITE_ACTIONS for s in segments):
            offenders.append(name)
    if offenders:
        raise RuntimeError(
            "Refusing to request permissions that are not read-only: "
            + ", ".join(offenders)
        )


def _acquire_setup_token(setup_client_id: str, tenant_id: str | None) -> tuple[str, str, str]:
    """Sign the administrator in and return (access token, tenant id, account).

    The default is the system browser (the sign-in page people already know,
    with their MFA and Conditional Access applying as usual); when no browser
    can be opened, for example on a headless or remote session, it falls back
    to the device code flow automatically. The tenant id and signed-in
    account come from the token's own claims, so nobody has to find and paste
    a Directory ID.
    """
    import msal

    authority = f"{LOGIN_BASE}/{tenant_id}" if tenant_id else f"{LOGIN_BASE}/organizations"
    pub_app = msal.PublicClientApplication(client_id=setup_client_id, authority=authority)

    result: dict | None = None
    try:
        typer.echo("Opening your browser for the Microsoft sign-in page...")
        result = pub_app.acquire_token_interactive(
            scopes=SETUP_SCOPES, prompt="select_account", timeout=300
        )
    except Exception:
        result = None
    if not result or "access_token" not in result:
        if result and result.get("error_description"):
            typer.echo(f"Browser sign-in did not complete: {result['error_description']}")
        typer.echo("Falling back to a device code sign-in (no browser needed on this machine).")
        flow = pub_app.initiate_device_flow(scopes=SETUP_SCOPES)
        if "user_code" not in flow:
            typer.echo(
                "Could not start the sign-in: "
                f"{flow.get('error_description', 'unknown error')}. "
                "Check the network and the sign-in app's client ID, then run setup again.",
                err=True,
            )
            raise typer.Exit(1)
        typer.echo("")
        typer.echo(f"  1. On any device, open: {flow['verification_uri']}")
        typer.echo(f"  2. Enter this code: {flow['user_code']}")
        typer.echo("  3. Sign in as a Global Administrator of the tenant to assess.")
        typer.echo("")
        typer.echo("Waiting for the sign-in...", nl=False)
        result = pub_app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            typer.echo(" it did not complete.", err=True)
            typer.echo(
                f"Microsoft said: {result.get('error_description', 'no detail')}. "
                "Run 'iamai setup' to try again.",
                err=True,
            )
            raise typer.Exit(1)
        typer.echo(" done.")

    claims = result.get("id_token_claims") or {}
    return (
        result["access_token"],
        str(claims.get("tid", "")),
        str(claims.get("preferred_username", "")),
    )


def _setup_get(token: str, path: str, params: dict | None = None) -> dict:
    resp = httpx.get(
        f"{GRAPH_BASE}/v1.0/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()


def _setup_post(token: str, path: str, body: dict) -> dict:
    resp = httpx.post(
        f"{GRAPH_BASE}/v1.0/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body,
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()


def _setup_patch(token: str, path: str, body: dict) -> None:
    resp = httpx.patch(
        f"{GRAPH_BASE}/v1.0/{path.lstrip('/')}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body,
        timeout=30.0,
    )
    resp.raise_for_status()


def _resolve_permission_guids(token: str) -> list[str]:
    """Return [permission_guid, ...] for PERMISSION_NAMES.

    Fetches the Microsoft Graph service principal from the signed-in tenant and
    resolves each permission name to its stable appRole id, so the app is
    created requesting exactly those read roles. The admin then consents to
    them through Microsoft's own screen; setup no longer grants them itself.
    """
    data = _setup_get(
        token,
        "servicePrincipals",
        {"$filter": f"appId eq '{GRAPH_APP_ID}'", "$select": "id,appRoles"},
    )
    graph_sp = data["value"][0]
    role_map = {role["value"]: role["id"] for role in graph_sp["appRoles"]}
    missing = [name for name in PERMISSION_NAMES if name not in role_map]
    if missing:
        typer.echo(f"Warning: could not resolve GUIDs for: {', '.join(missing)}", err=True)
    return [role_map[name] for name in PERMISSION_NAMES if name in role_map]


def _get_or_create_app(token: str, cert_der_b64: str, resource_access: list[dict]) -> tuple[str, str]:
    """Return (appId, objectId) for the IAMAI Collector app, creating it if absent."""
    existing = _setup_get(
        token,
        "applications",
        {"$filter": "displayName eq 'IAMAI Collector'", "$select": "id,appId"},
    )
    if existing.get("value"):
        found = existing["value"][0]
        typer.echo("Found existing 'IAMAI Collector' app registration; updating certificate.")
        _setup_patch(token, f"applications/{found['id']}", {
            "keyCredentials": [{"type": "AsymmetricX509Cert", "usage": "Verify", "key": cert_der_b64}],
        })
        return found["appId"], found["id"]

    created = _setup_post(token, "applications", {
        "displayName": "IAMAI Collector",
        "signInAudience": "AzureADMultipleOrgs",
        "keyCredentials": [{"type": "AsymmetricX509Cert", "usage": "Verify", "key": cert_der_b64}],
        "requiredResourceAccess": [{"resourceAppId": GRAPH_APP_ID, "resourceAccess": resource_access}],
    })
    typer.echo(f"Created app registration 'IAMAI Collector' (appId: {created['appId']}).")
    return created["appId"], created["id"]


def _get_or_create_sp(token: str, app_id: str) -> str:
    """Return the object ID of the service principal for app_id, creating it if absent."""
    existing = _setup_get(
        token,
        "servicePrincipals",
        {"$filter": f"appId eq '{app_id}'", "$select": "id"},
    )
    if existing.get("value"):
        return existing["value"][0]["id"]
    created = _setup_post(token, "servicePrincipals", {"appId": app_id})
    return created["id"]


# Admin consent is no longer granted programmatically. Doing so required
# AppRoleAssignment.ReadWrite.All, the one scope that can grant an app roles
# and, per Microsoft's own warning, lets an app grant privileges to itself.
# The signed-in Global Administrator now approves the app's read-only roles
# through Microsoft's admin-consent screen instead (the CONSENT_URL_TEMPLATE
# flow already used for a second tenant), so setup never holds that scope.


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _prompt_alias(default: str) -> str:
    """A short name for the tenant, validated and re-prompted, never crashed.

    The alias names folders on disk and appears in every report in place of
    the tenant's real name, so it must be a plain word."""
    while True:
        alias = typer.prompt(
            "A short name for this tenant, used in reports and folder names "
            "(letters, digits, - and _)",
            default=default or "tenant",
        ).strip()
        if _ALIAS_RE.match(alias):
            return alias
        typer.echo(
            f"  '{alias}' will not work as a folder name. Use letters, digits, "
            "hyphens and underscores, starting with a letter or digit."
        )


def _default_alias_from_account(account: str) -> str:
    """admin@contoso.com suggests 'contoso'; anything odd suggests nothing."""
    domain = account.partition("@")[2]
    label = domain.partition(".")[0]
    return label if _ALIAS_RE.match(label or "") else ""


@app.command()
def setup(
    tenant_id: str = typer.Option(
        None,
        "--tenant-id",
        help="Sign in to this specific tenant (for scripts and multi-tenant work); "
        "the interactive default reads the tenant from your sign-in instead.",
    ),
) -> None:
    """Connect a tenant: sign in, create the read-only Collector app, write config."""
    typer.echo("IAMAI setup")
    typer.echo("")
    typer.echo("This connects one tenant so IAMAI can read it. Four steps, about five")
    typer.echo("minutes: a one-time sign-in app, your sign-in, the read-only Collector")
    typer.echo("app, and the permission approval. Nothing here changes the tenant.")
    typer.echo("")

    if tenant_id is not None:
        tenant_id = _require_guid(tenant_id, "tenant ID")

    # --- Step 1 of 4: the one-time sign-in helper app --------------------------
    existing_config: Config | None = None
    try:
        existing_config = load_config()
    except Exception:
        existing_config = None

    setup_client_id = SETUP_CLIENT_ID
    if not setup_client_id and existing_config and existing_config.setupClientId:
        setup_client_id = existing_config.setupClientId
        typer.echo("Step 1 of 4: using the sign-in app from your existing config.")
    elif setup_client_id:
        typer.echo("Step 1 of 4: the sign-in app is already configured.")
    else:
        typer.echo("Step 1 of 4: create the one-time sign-in app.")
        typer.echo("")
        typer.echo("Setup signs you in through a small app registration of your own, so no")
        typer.echo("third party ever sits in the sign-in path. You create it once and it is")
        typer.echo("remembered. Two ways, either is fine:")
        typer.echo("")
        typer.echo("Fast path, if you have the Azure CLI and are signed in as a Global")
        typer.echo("Administrator (az login): this one command creates it and prints the")
        typer.echo("client ID to paste below:")
        typer.echo("")
        typer.echo('  az ad app create --display-name "IAMAI Setup" '
                   "--sign-in-audience AzureADMultipleOrgs "
                   "--is-fallback-public-client true --query appId -o tsv")
        typer.echo("")
        typer.echo("Manual path, about two minutes in the portal:")
        typer.echo("")
        typer.echo("  1. Open, signed in as a Global Administrator:")
        typer.echo("     https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade")
        typer.echo("     (or Entra ID > App registrations > New registration).")
        typer.echo('  2. Name: "IAMAI Setup"  |  Supported accounts: Any organizational directory '
                   "(multitenant)  |  Register.")
        typer.echo("  3. Authentication tab > Advanced settings > Allow public client flows: Yes > Save.")
        typer.echo("  4. Copy the Application (client) ID from the Overview page.")
        typer.echo("")
        while True:
            setup_client_id = typer.prompt(
                "Paste the sign-in app's client ID (a GUID like 12345678-abcd-...)"
            ).strip()
            if _GUID_RE.match(setup_client_id):
                break
            typer.echo("  That is not a GUID. Copy the Application (client) ID from the app's Overview page.")

    # --- Step 2 of 4: sign in --------------------------------------------------
    typer.echo("")
    typer.echo("Step 2 of 4: sign in to the tenant you are assessing.")
    typer.echo("")
    typer.echo("Your browser will open the Microsoft sign-in page. Sign in as a Global")
    typer.echo("Administrator of the tenant you want assessed; your usual MFA and access")
    typer.echo("policies apply. This sign-in requests exactly one permission:")
    typer.echo("")
    for scope in SETUP_SCOPES:
        typer.echo(f"  {scope.rsplit('/', 1)[-1]}")
    typer.echo("")
    typer.echo("It lets setup create the IAMAI Collector app and manage only that app.")
    typer.echo("It cannot read or change anything else, and it is used only during setup.")
    typer.echo("The Collector app itself gets read-only permissions, shown in step 3.")
    typer.echo("")

    token, signed_in_tenant, account = _acquire_setup_token(setup_client_id, tenant_id)
    signed_in_tenant = _require_guid(signed_in_tenant, "tenant ID from the sign-in")

    if tenant_id is not None and signed_in_tenant.lower() != tenant_id.lower():
        typer.echo(
            f"You asked for tenant {tenant_id} but signed in to {signed_in_tenant}. "
            "Nothing was changed. Run setup again and sign in with an account from "
            "the right tenant.",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo("")
    typer.echo(f"Signed in as {account}")
    typer.echo(f"Tenant ID: {signed_in_tenant}")
    if not typer.confirm("Is this the tenant you want assessed?", default=True):
        typer.echo("Nothing was changed. Run setup again and pick the right account "
                   "in the sign-in window.")
        raise typer.Exit(1)

    known_alias = ""
    if existing_config:
        for alias_name, known_tid in existing_config.tenants.items():
            if known_tid.lower() == signed_in_tenant.lower():
                known_alias = alias_name
    if known_alias:
        alias = known_alias
        typer.echo(f"This tenant is already configured as '{alias}'; refreshing it.")
    else:
        alias = _prompt_alias(_default_alias_from_account(account))

    # --- Step 3 of 4: the read-only Collector app ------------------------------
    typer.echo("")
    typer.echo("Step 3 of 4: the read-only Collector app and its certificate.")
    typer.echo("")
    typer.echo("The Collector is what reads the tenant on your schedule. It asks for")
    typer.echo("these permissions, every one a read permission:")
    typer.echo("")
    for name, why in PERMISSION_TABLE:
        typer.echo(f"  {name:<36} {why}")
    typer.echo("")
    # The read-only promise, enforced in code rather than by convention: if
    # this table ever gained a write permission, setup would refuse to run.
    assert_permissions_read_only(PERMISSION_NAMES)

    home_tenant = existing_config.homeTenantId if existing_config else signed_in_tenant
    # The Collector app is registered once, in the first tenant that ran
    # setup, and every further tenant only approves it. Creating a second
    # copy per tenant would mean a credential and an app to look after in
    # every client tenant instead of one.
    creating = (
        existing_config is None
        or not existing_config.appId
        or signed_in_tenant.lower() == home_tenant.lower()
    )

    cert_pem, cert_public_pem = CERT_PEM(), CERT_PUBLIC_PEM()
    if creating:
        cert_pem.parent.mkdir(parents=True, exist_ok=True)
        if cert_pem.exists():
            typer.echo(f"Certificate already exists at {cert_pem}, keeping it.")
            # Harden it even though we did not just create it: a key generated
            # before this hardening existed would otherwise stay world-readable,
            # since this branch never rewrites it (SECRETS-2-001).
            _harden_key_file(cert_pem)
        else:
            generate_certificate(cert_pem, cert_public_pem)
            typer.echo(f"Generated a new sign-in certificate (valid {CERT_LIFETIME_DAYS} days).")

        cert_obj = x509.load_pem_x509_certificate(cert_public_pem.read_bytes())
        cert_der_b64 = base64.b64encode(cert_obj.public_bytes(serialization.Encoding.DER)).decode("ascii")

        typer.echo("Looking up the permission identifiers from Microsoft Graph...")
        perm_guids = _resolve_permission_guids(token)
        resource_access = [{"id": guid, "type": "Role"} for guid in perm_guids]

        typer.echo("Creating the app registration...")
        app_id, _app_obj_id = _get_or_create_app(token, cert_der_b64, resource_access)
        # Graph assigns this, so it is trusted, but config.yaml is emitted by a
        # hand-rolled writer that does not escape values; validating it is a
        # GUID keeps anything but a GUID out of that file (INJECT-2-001).
        app_id = _require_guid(app_id, "application ID from Graph")

        typer.echo("Creating its service principal...")
        _get_or_create_sp(token, app_id)
    else:
        app_id = existing_config.appId
        typer.echo("The Collector app already exists (created when the first tenant was")
        typer.echo("connected), so nothing new is created here. This tenant only needs")
        typer.echo("to approve it, which is step 4.")

    tenants: dict[str, str] = dict(existing_config.tenants) if existing_config else {}
    tenants[alias] = signed_in_tenant
    config = Config(
        appId=app_id,
        homeTenantId=home_tenant,
        certPath=str(cert_pem),
        setupClientId=setup_client_id,
        tenants=tenants,
    )
    config_path = save_config(config)

    # --- Step 4 of 4: approve, and here is everything that was configured ------
    consent_url = CONSENT_URL_TEMPLATE.format(tenantId=signed_in_tenant, appId=app_id)
    typer.echo("")
    typer.echo("Step 4 of 4: approve the read-only permissions.")
    typer.echo("")
    typer.echo("What was configured:")
    typer.echo(f"  Tenant:      {alias} ({signed_in_tenant})")
    typer.echo(f"  Config file: {config_path}")
    try:
        not_after = x509.load_pem_x509_certificate(cert_public_pem.read_bytes()).not_valid_after_utc
        typer.echo(f"  Certificate: {cert_pem}, expires {not_after.date()}")
    except OSError:
        pass
    typer.echo("")
    typer.echo("The app exists but can read nothing until an administrator approves it:")
    typer.echo(f"  1. Open this link, still signed in as a Global Administrator: {consent_url}")
    typer.echo("  2. Review the list (every permission is a read permission) and Accept.")
    typer.echo(f"  3. Confirm it worked: iamai verify {alias}")
    typer.echo("")
    typer.echo(f"Then read the tenant with: iamai collect {alias}")
    typer.echo("To connect another tenant later, run 'iamai setup' again, or "
               "'iamai consent <alias>' for its approval link.")


@app.command()
def consent(alias: str) -> None:
    """Print the admin consent URL for a tenant."""
    config = load_config()
    tenant_id = config.tenant_id(alias)
    url = CONSENT_URL_TEMPLATE.format(tenantId=tenant_id, appId=config.appId)
    typer.echo(f"Ask an administrator of tenant '{alias}' to open this link and accept:")
    typer.echo(f"  {url}")


def _verify_checks(client: GraphClient) -> list[tuple[str, str, str]]:
    """One minimal read per permission. Returns (permission, status, detail)."""

    def simple(path: str, params: dict | None = None):
        def check():
            client.get(path, params=params)
        return check

    def auth_methods_check():
        body = client.get("v1.0/users", params={"$top": "1", "$select": "id"})
        users_page = body.get("value", [])
        if not users_page:
            raise GraphError(0, "no_users", "Tenant returned no users to test against.")
        client.get(f"v1.0/users/{users_page[0]['id']}/authentication/methods")

    checks: list[tuple[str, object]] = [
        ("Policy.Read.All", simple("v1.0/identity/conditionalAccess/policies", {"$top": "1"})),
        ("Directory.Read.All", simple("v1.0/users", {"$top": "1", "$select": "id"})),
        ("AuditLog.Read.All", simple("v1.0/auditLogs/signIns", {"$top": "1"})),
        ("UserAuthenticationMethod.Read.All", auth_methods_check),
        ("Reports.Read.All", simple("v1.0/reports/authenticationMethods/userRegistrationDetails", {"$top": "1"})),
        ("Organization.Read.All", simple("v1.0/subscribedSkus")),
        ("Domain.Read.All", simple("v1.0/domains")),
        # roleDefinitions supports only $filter (eq/in on id, displayName, isBuiltIn)
        # and $expand; $top returns 400 Request_UnsupportedQuery (ASSUMPTIONS.md note 18).
        ("RoleManagement.Read.Directory", simple("v1.0/roleManagement/directory/roleDefinitions", {"$filter": f"id eq '{GA_ROLE_TEMPLATE_ID}'"})),
        ("Application.Read.All", simple("v1.0/servicePrincipals", {"$top": "1", "$select": "id"})),
        ("IdentityRiskyUser.Read.All", simple("v1.0/identityProtection/riskyUsers", {"$top": "1"})),
    ]

    results: list[tuple[str, str, str]] = []
    for permission, check in checks:
        try:
            check()
            results.append((permission, "PASS", ""))
        except GraphError as exc:
            if permission == "IdentityRiskyUser.Read.All" and "license" in exc.message.lower():
                results.append((permission, "WARN", "Requires an Entra ID P2 license; consent itself looks fine."))
            else:
                results.append((permission, "FAIL", f"{exc.status_code} {exc.code}"))
        except Exception as exc:
            results.append((permission, "FAIL", f"{type(exc).__name__}"))
    return results


@app.command()
def verify(alias: str) -> None:
    """Test every permission with a real read and print a pass/fail table."""
    config = load_config()
    client = make_client(config, config.tenant_id(alias))
    results = _verify_checks(client)

    typer.echo(f"Permission check for tenant '{alias}'")
    typer.echo("")
    typer.echo(f"  {'Permission':<36} {'Result':<7} Detail")
    typer.echo(f"  {'-' * 36} {'-' * 7} {'-' * 40}")
    failed = False
    for permission, status, detail in results:
        typer.echo(f"  {permission:<36} {status:<7} {detail}")
        if status == "FAIL":
            failed = True
    typer.echo("")
    if failed:
        typer.echo("At least one permission failed. Check that every permission in the table was added and admin consent was granted.")
        raise typer.Exit(code=1)
    typer.echo("All permissions verified.")


def _install_method() -> str:
    prefix = sys.prefix.replace("\\", "/").lower()
    if "/pipx/" in prefix or prefix.endswith("/pipx"):
        return "pipx (isolated app install)"
    if "/.iamai/" in prefix:
        return "the one-line installer's environment"
    if prefix.endswith("/.venv") or "/venv" in prefix:
        return "a virtual environment (likely a source checkout)"
    return "the system Python"


def _doctor_rows(offline: bool) -> list[tuple[str, str, str]]:
    """Every check the doctor runs, as (check, status, plain detail).

    Each row answers something a person would otherwise diagnose by hand:
    what is installed and from where, whether the config and credential are
    usable, which standard grades, whether Microsoft is reachable, and per
    tenant whether the read permissions are actually consented.
    """
    rows: list[tuple[str, str, str]] = []

    rows.append(("Version", "OK", f"iamai {TOOL_VERSION}, installed via {_install_method()}"))
    py = "%d.%d.%d" % sys.version_info[:3]
    rows.append(("Python", "OK", f"{py} at {sys.executable}"))

    from iamai.paths import config_path

    config = None
    try:
        config = load_config()
        aliases = ", ".join(sorted(config.tenants)) or "(none)"
        rows.append(("Config", "OK", f"{config_path()}; tenants: {aliases}"))
    except FileNotFoundError:
        rows.append(("Config", "FAIL", f"Not found at {config_path()}. Run 'iamai setup' first."))
    except Exception as exc:
        rows.append(("Config", "FAIL", f"Unreadable: {exc}. Run 'iamai setup' to rewrite it."))

    if config is not None:
        cert_file = Path(config.certPath)
        try:
            cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
            not_after = cert.not_valid_after_utc
            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (not_after - now).days
            if now >= not_after:
                rows.append(("Certificate", "FAIL",
                             f"Expired on {not_after.date()}. Run 'iamai setup' to renew it."))
            elif days_left <= CERT_RENEW_WARNING_DAYS:
                rows.append(("Certificate", "WARN",
                             f"Expires in {days_left} day(s), on {not_after.date()}. "
                             "Run 'iamai setup' before then."))
            else:
                rows.append(("Certificate", "OK", f"Valid until {not_after.date()} ({days_left} days)"))
        except OSError:
            rows.append(("Certificate", "FAIL",
                         f"Not found at {cert_file}. Run 'iamai setup' to create one."))
        except ValueError:
            rows.append(("Certificate", "FAIL",
                         f"The file at {cert_file} is not a readable certificate. Run 'iamai setup'."))

    try:
        standard_path = _latest_baseline_path()
        artifact = json.loads(standard_path.read_text(encoding="utf-8"))
        count = len(artifact.get("controls", []))
        if standard_path == DEFAULT_PACK:
            detail = f"The standard that ships with the tool ({count} controls)"
        else:
            detail = f"{standard_path.name} ({count} controls)"
        rows.append(("Standard", "OK", detail))
    except Exception as exc:
        rows.append(("Standard", "FAIL", f"No usable standard: {exc}"))

    if offline:
        rows.append(("Graph connectivity", "SKIP", "Offline mode; network checks not run."))
        return rows

    # The only two hosts this tool is ever allowed to reach. Any HTTP answer,
    # including 401, proves reachability; only a transport failure does not.
    for label, url in (
        ("graph.microsoft.com", "https://graph.microsoft.com/v1.0/$metadata"),
        ("login.microsoftonline.com",
         "https://login.microsoftonline.com/common/.well-known/openid-configuration"),
    ):
        try:
            httpx.get(url, timeout=10)
            rows.append((label, "OK", "Reachable"))
        except Exception as exc:
            rows.append((label, "FAIL",
                         f"Not reachable ({type(exc).__name__}). Check the network or proxy."))

    if config is not None:
        for alias in sorted(config.tenants):
            try:
                client = make_client(config, config.tenant_id(alias))
                results = _verify_checks(client)
            except typer.Exit:
                rows.append((f"Consent ({alias})", "FAIL",
                             "The certificate has expired; run 'iamai setup' to renew it."))
                continue
            except Exception as exc:
                rows.append((f"Consent ({alias})", "FAIL",
                             f"Could not sign in: {type(exc).__name__}. "
                             f"Run 'iamai verify {alias}' for the full story."))
                continue
            failed = [p for p, status, _ in results if status == "FAIL"]
            if failed:
                rows.append((f"Consent ({alias})", "FAIL",
                             f"Missing or unconsented: {', '.join(failed)}. "
                             f"Run 'iamai consent {alias}' and have an administrator accept."))
            else:
                warned = sum(1 for _, status, _ in results if status == "WARN")
                detail = f"All {len(results)} read permissions answer"
                if warned:
                    detail += f" ({warned} with a license note; 'iamai verify {alias}' has it)"
                rows.append((f"Consent ({alias})", "OK", detail))
    return rows


@app.command()
def doctor(
    offline: bool = typer.Option(
        False, "--offline", help="Skip the network and per-tenant permission checks."
    ),
) -> None:
    """Check the install, config, credential, standard and consent in one go."""
    typer.echo("IAMAI doctor")
    typer.echo("")
    rows = _doctor_rows(offline)
    width = max(len(check) for check, _, _ in rows) + 2
    typer.echo(f"  {'Check':<{width}} {'Result':<7} Detail")
    typer.echo(f"  {'-' * width} {'-' * 7} {'-' * 50}")
    failed = False
    for check, status, detail in rows:
        typer.echo(f"  {check:<{width}} {status:<7} {detail}")
        if status == "FAIL":
            failed = True
    typer.echo("")
    if failed:
        typer.echo("At least one check failed. Each failing row above says what to run next.")
        raise typer.Exit(code=1)
    typer.echo("Everything checks out.")


@app.command()
def collect(
    alias: str,
    days: int = typer.Option(30, "--days", help="How many days of sign-in logs to pull."),
) -> None:
    """Run all collectors and write an immutable snapshot."""
    from iamai.collectors import run_all
    from iamai.store import SnapshotStore

    config = load_config()
    client = make_client(config, config.tenant_id(alias))
    store = SnapshotStore()
    writer = store.new_snapshot(alias)

    # Live feedback: each collector is a network round trip and the whole pull
    # runs sequentially, so without this the command looks stuck for a minute.
    # Progress goes to stderr so a redirected stdout keeps only the summary.
    def _progress(event: str, dataset: str, index: int, total: int) -> None:
        if event == "start":
            typer.echo(f"  [{index:>2}/{total}] {dataset} ...", err=True, nl=False)
        else:
            typer.echo(" done", err=True)

    manifest = run_all(client, writer, alias, days=days, progress=_progress)

    typer.echo("")
    typer.echo(f"Snapshot written to {writer.snapshot_dir}")
    typer.echo("")
    typer.echo(f"  {'Dataset':<30} {'Items':>7} {'Seconds':>8} Status")
    typer.echo(f"  {'-' * 30} {'-' * 7} {'-' * 8} {'-' * 20}")
    for record in manifest.datasets:
        if record.skipped:
            status = "skipped"
        elif record.complete:
            status = "ok"
        else:
            status = "PARTIAL"
        typer.echo(
            f"  {record.dataset:<30} {record.count:>7} {record.durationSeconds:>8.1f} {status}"
        )
    typer.echo("")
    if manifest.complete:
        typer.echo("Collection complete.")
    else:
        typer.echo("Collection finished with errors. The snapshot is marked partial and the assessment will say so honestly.")


@app.command()
def sanitize(alias: str) -> None:
    """Produce a pseudonymized copy of the latest snapshot."""
    from iamai.sanitize import sanitize_snapshot
    from iamai.store import SnapshotStore

    config = load_config()
    # Every other alias-taking command checks the alias against the
    # configured tenants before touching the filesystem; this was the one
    # exception (AUTHZ-002). The check itself is what matters here, not the
    # tenant id it returns.
    config.tenant_id(alias)
    store = SnapshotStore()
    snapshot_dir = store.latest_snapshot(alias)
    map_path = store.alias_dir(alias) / "pseudo_map.json"
    out_dir = sanitize_snapshot(snapshot_dir, map_path)
    typer.echo(f"Sanitized copy written to {out_dir}")
    typer.echo(f"Mapping file (never commit, never share): {map_path}")


@app.command()
def purge(
    alias: str,
    older_than: int = typer.Option(
        None, "--older-than", help="Delete snapshots older than this many days."
    ),
    keep_latest: int = typer.Option(
        None, "--keep-latest", help="Delete every snapshot except the most recent N."
    ),
    all_data: bool = typer.Option(
        False, "--all",
        help="Delete everything for this alias: every snapshot, assessment, plan, "
             "the answers file and the pseudonym map. Use when an engagement has ended.",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Delete without asking."),
) -> None:
    """Delete collected tenant data that is no longer needed.

    Every collect leaves a full copy of real names, sign-in history, and
    until sanitized, IP and location data on disk, and nothing else in this
    tool ever removes it (RETENTION-001). This is the tool-level answer to
    "what tenant data do we still have, and should we still have it," for an
    MSP running this repeatedly across many client tenants over time.
    """
    import shutil

    from iamai.store import SnapshotStore

    config = load_config()
    config.tenant_id(alias)
    store = SnapshotStore()
    alias_dir = store.alias_dir(alias)

    modes = [name for name, chosen in (
        ("--older-than", older_than is not None),
        ("--keep-latest", keep_latest is not None),
        ("--all", all_data),
    ) if chosen]
    if len(modes) != 1:
        typer.echo(
            "Pick exactly one of --older-than, --keep-latest or --all, so what "
            "gets deleted is never a guess.",
            err=True,
        )
        raise typer.Exit(code=1)

    if all_data:
        if not alias_dir.exists():
            typer.echo(f"Nothing on disk for '{alias}'.")
            return
        typer.echo(f"This deletes everything under {alias_dir}: every snapshot, "
                    "assessment, plan, the answers file and the pseudonym map.")
        if not yes and not typer.confirm(f"Delete all data for '{alias}'?", default=False):
            typer.echo("Not deleted.")
            raise typer.Exit(code=1)
        shutil.rmtree(alias_dir)
        typer.echo(f"Deleted {alias_dir}.")
        # Imported standards live under baselines/, outside the alias dir, so
        # they are not removed here. One frozen by an older version's
        # reference-tenant capture can carry that tenant's policy names and
        # network ranges, so point at the folder rather than deleting a shared
        # standard on the operator's behalf (CRYPTO-2-004).
        baselines = sorted(_baselines_dir().glob("baseline-v*.json")) if _baselines_dir().exists() else []
        if baselines:
            typer.echo(
                f"Note: {len(baselines)} frozen standard(s) remain under "
                f"{_baselines_dir()}/. If one was captured from this tenant by an "
                "older version of this tool, delete it by hand."
            )
        return

    condemned = store.snapshots_to_purge(
        alias, older_than_days=older_than, keep_latest=keep_latest
    )
    if not condemned:
        typer.echo(f"Nothing to delete for '{alias}'.")
        return
    typer.echo(f"This deletes {len(condemned)} snapshot(s), keeping the rest:")
    for path in condemned:
        typer.echo(f"  {path}")
    if not yes and not typer.confirm("Delete these snapshots?", default=False):
        typer.echo("Not deleted.")
        raise typer.Exit(code=1)
    for path in condemned:
        shutil.rmtree(path)
    typer.echo(f"Deleted {len(condemned)} snapshot(s). Assessments, plans, answers, "
                "and the pseudonym map are untouched; use --all to remove those too.")


baseline_app = typer.Typer(
    add_completion=False,
    pretty_exceptions_show_locals=False,
    help="Manage the standard used for grading (the shipped one is the default).",
)
app.add_typer(baseline_app, name="baseline")

# The standard that ships with the tool, used when no baseline has been built.
# Loaded as bundled package data (importlib.resources), so it is found whether
# the tool runs from a checkout, a pipx install, or a frozen binary, rather than
# from a path relative to the source tree that only exists in a checkout.
import importlib.resources  # noqa: E402

DEFAULT_PACK = importlib.resources.files("iamai") / "packs" / "basics-v1.json"
TOOL_VERSION = "1.2.0"


def _baselines_dir():
    from iamai.paths import baselines_dir
    return baselines_dir()


def _next_baseline_path() -> Path:
    _baselines_dir().mkdir(parents=True, exist_ok=True)
    version = 1
    while (_baselines_dir() / f"baseline-v{version}.json").exists():
        version += 1
    return _baselines_dir() / f"baseline-v{version}.json"


def _load_standard(pack: Path | None) -> tuple[dict, dict]:
    """Load the active standard and describe it for the report.

    Every assessment and report states which standard graded it, so a grade
    can never be read without knowing what it was measured against."""
    path = Path(pack) if pack else _latest_baseline_path()
    artifact = json.loads(path.read_text(encoding="utf-8"))
    built = artifact.get("builtFrom") or {}
    shipped = path == DEFAULT_PACK
    descriptor = {
        "source": "shipped" if shipped else "imported",
        "name": ("the standard that ships with this tool" if shipped
                 else f"an imported standard ({path.name})"),
        "version": str(built.get("version") or ""),
        "schemaVersion": artifact.get("schemaVersion"),
        "controls": len(artifact.get("controls", [])),
        "file": path.name,
    }
    return artifact, descriptor


def _latest_baseline_path() -> Path:
    candidates = sorted(
        _baselines_dir().glob("baseline-v*.json"),
        key=lambda p: int(p.stem.split("-v")[-1]) if p.stem.split("-v")[-1].isdigit() else 0,
    )
    if not candidates:
        # The standard ships with the tool: fixed, versioned, and the same for
        # every tenant, which is what makes grades comparable across tenants
        # and across time. An imported pack under baselines/ overrides it for
        # whoever authored their own; with none imported, this is the default.
        if DEFAULT_PACK.is_file():
            return DEFAULT_PACK
        raise FileNotFoundError(
            "No standard to grade against: the packaged standard is missing "
            "from this install and nothing was imported with 'iamai baseline "
            "import'. Reinstall the tool."
        )
    return candidates[-1]


@baseline_app.command("import")
def baseline_import(
    pack_path: Path = typer.Argument(..., help="Path to a standard pack JSON file (see packs/)."),
) -> None:
    """Validate an authored standard pack and freeze it as the active baseline.

    A pack is tenant free: it grades any tenant as it is. The import runs the
    schema and static checks (citations present, known profiles, no tenant
    GUIDs outside universal constants and slots) and refuses to freeze a pack
    that fails any of them."""
    import json as _json

    from iamai.canon import validate_pack

    if not pack_path.exists():
        typer.echo(f"No pack found at {pack_path}.", err=True)
        raise typer.Exit(code=1)
    try:
        artifact = _json.loads(pack_path.read_text(encoding="utf-8"))
    except _json.JSONDecodeError as exc:
        typer.echo(f"The pack at {pack_path} is not valid JSON: {exc}.", err=True)
        raise typer.Exit(code=1)

    errors = validate_pack(artifact)
    if errors:
        typer.echo(f"The pack at {pack_path} did not pass validation:", err=True)
        for error in errors:
            typer.echo(f"  - {error}", err=True)
        raise typer.Exit(code=1)

    controls = artifact.get("controls", [])
    profiles: dict[str, int] = {}
    for control in controls:
        profile = str(control.get("profile", "baseline"))
        profiles[profile] = profiles.get(profile, 0) + 1

    path = _next_baseline_path()
    path.write_text(_json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    typer.echo(f"Pack validated and frozen as the active baseline: {path}")
    summary = ", ".join(f"{count} {name}" for name, count in sorted(profiles.items()))
    typer.echo(f"  {len(controls)} controls ({summary}).")
    typer.echo("Run 'iamai assess <alias>' to grade a tenant against it.")


def _echo_assessment(assessment: dict, baseline_name: str) -> None:
    counts = assessment["gradeCounts"]
    total = len(assessment["controls"])
    typer.echo(f"Assessment of '{assessment['alias']}' against {baseline_name} ({total} controls)")
    typer.echo("")
    order = ["FULL", "FUNCTIONAL", "PARTIAL", "MISSING", "UNKNOWN"]
    typer.echo("  " + "   ".join(f"{grade}: {counts.get(grade, 0)}" for grade in order))
    typer.echo("")
    typer.echo(f"  {'Control':<24} {'Grade':<11} Detail")
    typer.echo(f"  {'-' * 24} {'-' * 11} {'-' * 44}")
    from iamai.grade import _with_names

    names = assessment.get("names") or {}
    for result in assessment["controls"]:
        detail = (result["coverageGaps"] or result["notes"] or [""])[0]
        detail = _with_names(detail, names, set())
        typer.echo(f"  {result['controlId']:<24} {result['grade']:<11} {detail}")
    structural = [
        (result["controlId"], finding)
        for result in assessment["controls"]
        for finding in result.get("structural") or []
    ]
    if structural:
        typer.echo("")
        typer.echo(
            f"  Organization notes ({len(structural)}). These do not affect any grade. "
            "The protection is already in place."
        )
        for control_id, finding in structural:
            typer.echo(f"    {control_id}: {_with_names(finding, names, set())}")

    if assessment["surplus"]:
        typer.echo("")
        typer.echo(f"  Surplus (outside the standard, not penalized): {len(assessment['surplus'])}")
        for item in assessment["surplus"]:
            typer.echo(f"    {item['displayName']} ({item['type']})")
    if assessment["unknowns"]:
        typer.echo("")
        typer.echo("  Unknowns, stated honestly:")
        for item in assessment["unknowns"]:
            typer.echo(f"    {item}")


@app.command()
def assess(
    alias: str,
    pack: Path = typer.Option(
        None,
        "--pack",
        help="Grade against this standard pack file instead of the active standard.",
        exists=True,
        dir_okay=False,
    ),
) -> None:
    """Grade the latest snapshot against the standard and write assessment.json.

    The standard ships with the tool: fixed, versioned, and the same for
    every tenant, which is what makes grades comparable across tenants and
    across time. Every assessment records which standard and version graded
    it. An imported pack, when one exists, overrides the shipped one.
    """
    from iamai.grade import UNKNOWN
    from iamai.questions import assess_with_answers
    from iamai.store import SnapshotStore

    config = load_config()
    artifact, standard = _load_standard(pack)
    baseline_path = Path(pack) if pack else _latest_baseline_path()
    store = SnapshotStore()

    assessment, out_path, report_path, answer_count = assess_with_answers(
        alias, config.tenant_id(alias), artifact, store, standard=standard
    )

    if answer_count:
        plural = "answers" if answer_count != 1 else "answer"
        typer.echo(f"Applied {answer_count} saved questionnaire {plural}.")
    _echo_assessment(assessment, baseline_path.name)
    typer.echo("")
    typer.echo(f"Assessment written to {out_path}")
    typer.echo(f"Report written to {report_path} (open in a browser; print to PDF to keep a copy)")
    if assessment["gradeCounts"].get(UNKNOWN, 0):
        typer.echo("Some controls are UNKNOWN because data was incomplete. Re-run collect and assess again.")


# ---------------------------------------------------------------------------
# Questionnaire (M3): CLI runner and web wizard, two renderers of the same
# question definitions. All business logic lives in iamai.questions.
# ---------------------------------------------------------------------------


def _prompt_for_question(question) -> tuple[list[str] | str, str]:
    """Collect raw input for one question. Validation happens in make_answer."""
    if question.answerType == "freeText":
        return typer.prompt("Your answer (press Enter to leave blank)", default="", show_default=False), ""
    if question.answerType == "selectOne":
        # Listing every option (350+ timezones) is unusable in a terminal, so
        # type the value; make_answer validates it against the option set.
        options = {option.value for option in question.options}
        default = "UTC" if "UTC" in options else question.options[0].value
        entry = typer.prompt(f"Type your choice, for example {default}", default=default).strip()
        return entry, ""
    if question.answerType == "singleChoice":
        for index, option in enumerate(question.options, start=1):
            typer.echo(f"    {index}. {option.label}")
        entry = typer.prompt("Enter the number of your choice").strip()
        value = entry
        if entry.isdigit() and 1 <= int(entry) <= len(question.options):
            value = question.options[int(entry) - 1].value
        note = ""
        if value == "other":
            note = typer.prompt("Describe it in a few words")
        return value, note
    if question.answerType == "confirmSet":
        selected = [
            option.value
            for option in question.options
            if typer.confirm(f"    Is '{option.label}' a service account?", default=False)
        ]
        return selected, ""
    for index, option in enumerate(question.options, start=1):
        typer.echo(f"    {index}. {option.label}")
    entry = typer.prompt(
        "Enter numbers separated by commas, type names to add your own, or enter none",
        default="none",
    ).strip()
    if not entry or entry.lower() == "none":
        return [], ""
    raw: list[str] = []
    for token in entry.split(","):
        token = token.strip()
        if not token:
            continue
        if token.isdigit() and 1 <= int(token) <= len(question.options):
            raw.append(question.options[int(token) - 1].value)
        else:
            raw.append(token)
    return raw, ""


@app.command()
def questions(alias: str) -> None:
    """Answer the questionnaire in the terminal, then regrade automatically."""
    import json as _json

    from iamai.questions import (
        assess_with_answers,
        generate_questions,
        grade_changes,
        latest_assessment,
        load_answers,
        make_answer,
        pending_questions,
        save_answer,
    )
    from iamai.store import SnapshotStore, load_snapshot_data

    config = load_config()
    tenant_id = config.tenant_id(alias)
    artifact, standard = _load_standard(None)
    store = SnapshotStore()
    try:
        assessment = latest_assessment(store, alias)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1)
    snapshot_dir = store.latest_snapshot(alias)
    data, _ = load_snapshot_data(snapshot_dir)
    answers = load_answers(store.alias_dir(alias), tenant_id, alias)
    all_questions = generate_questions(assessment, data, snapshot_dir)
    pending = pending_questions(all_questions, answers)

    if not pending:
        typer.echo("Every question is already answered. Regrading with the saved answers.")
    for question in pending:
        position = all_questions.index(question) + 1
        typer.echo("")
        typer.echo(f"Question {position} of {len(all_questions)}")
        typer.echo(f"  {question.text}")
        typer.echo(f"  Why we ask: {question.trigger}")
        if question.evidence.rows:
            typer.echo("  What the data shows:")
            for row in question.evidence.rows:
                typer.echo(f"    {row.get('item', ''):<40} {row.get('detail', '')}")
        while True:
            raw, note = _prompt_for_question(question)
            try:
                answer = make_answer(question, raw, data, note=note)
            except ValueError as exc:
                typer.echo(f"  {exc}")
                continue
            break
        save_answer(store.alias_dir(alias), answers, answer)

    regraded, out_path, report_path, _ = assess_with_answers(alias, tenant_id, artifact, store, standard=standard)
    changes = grade_changes(assessment, regraded)
    typer.echo("")
    typer.echo("Answers saved. The assessment was regraded with them.")
    if changes:
        for change in changes:
            typer.echo(f"  Control {change['controlId']} moved from {change['from']} to {change['to']}.")
    else:
        typer.echo("  No grades changed. The answers are saved and will be used by the plan.")
    typer.echo("")
    _echo_assessment(regraded, standard.get("file", "the standard"))
    typer.echo("")
    typer.echo(f"Assessment written to {out_path}")
    typer.echo(f"Report written to {report_path} (open in a browser; print to PDF to keep a copy)")


@app.command()
def plan(
    alias: str,
    start_date: str = typer.Option(
        None,
        "--start-date",
        help="Rollout start date as YYYY-MM-DD. Defaults to today in the report timezone.",
    ),
    pack: Path = typer.Option(
        None,
        "--pack",
        help="The standard the assessment was graded against. Pass the same one here as "
             "to 'assess', or findings from controls it does not contain get no step.",
        exists=True,
        dir_okay=False,
    ),
) -> None:
    """Generate the remediation plan (requires an assessment and answers)."""
    import json as _json

    if start_date is not None:
        from datetime import date as _date

        try:
            _date.fromisoformat(start_date)
        except ValueError:
            typer.echo(
                f"'{start_date}' is not a date. Give the start date as YYYY-MM-DD, for example 2026-07-20.",
                err=True,
            )
            raise typer.Exit(code=1)

    from iamai.plan import generate_plan
    from iamai.questions import (
        generate_questions,
        latest_assessment,
        load_answers,
        pending_questions,
    )
    from iamai.report import render_plan
    from iamai.store import SnapshotStore, load_snapshot_data

    config = load_config()
    tenant_id = config.tenant_id(alias)
    baseline_path = Path(pack) if pack else _latest_baseline_path()
    artifact = _json.loads(baseline_path.read_text(encoding="utf-8"))
    store = SnapshotStore()
    try:
        assessment = latest_assessment(store, alias)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1)
    snapshot_dir = store.latest_snapshot(alias)
    data, _ = load_snapshot_data(snapshot_dir)
    answers = load_answers(store.alias_dir(alias), tenant_id, alias)
    pending = [
        q for q in pending_questions(generate_questions(assessment, data, snapshot_dir), answers)
        if q.required
    ]
    if pending:
        typer.echo(
            "The plan needs the questionnaire's answers first. Unanswered: "
            + ", ".join(q.id for q in pending) + ".",
            err=True,
        )
        typer.echo(f"Run 'iamai wizard {alias}' or 'iamai questions {alias}' first.", err=True)
        raise typer.Exit(code=1)

    plan_record = generate_plan(
        assessment, answers, artifact, data,
        tenant_id=tenant_id, alias=alias, start_date=start_date,
    )

    out_dir = store.alias_dir(alias) / "plans"
    out_dir.mkdir(parents=True, exist_ok=True)
    import time as _time
    stamp = _time.strftime("%Y%m%dT%H%M%SZ", _time.gmtime())
    stem = stamp
    suffix = 1
    while (out_dir / f"{stem}-plan.json").exists():
        stem = f"{stamp}-{suffix}"
        suffix += 1
    json_path = out_dir / f"{stem}-plan.json"
    json_path.write_text(
        _json.dumps(plan_record, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    html_path = out_dir / f"{stem}-plan.html"
    html_path.write_text(render_plan(plan_record), encoding="utf-8")

    steps = plan_record["steps"]
    typer.echo(f"Remediation plan for '{alias}' ({len(steps)} steps)")
    typer.echo(f"Start date: {plan_record['startDate']}")
    typer.echo("")
    for phase in plan_record["phases"]:
        phase_steps = [s for s in steps if s["phase"] == phase["number"]]
        typer.echo(f"  Phase {phase['number']} ({phase['days']}): {phase['name']}, checkpoint {phase['gateId']}")
        typer.echo(f"    {phase['dates']}")
        for step in phase_steps:
            typer.echo(f"    {step['id']}  {step['title']}")
    if plan_record["notIncluded"]:
        typer.echo("")
        typer.echo(f"  Not included (license): {len(plan_record['notIncluded'])} protection(s), reasons in the plan.")
    typer.echo("")
    typer.echo(f"Plan written to {json_path}")
    typer.echo(f"Printable plan written to {html_path} (open in a browser; print to PDF to keep a copy)")


@app.command()
def wizard(
    alias: str,
    port: int = typer.Option(8765, "--port", help="Local port for the wizard."),
) -> None:
    """Answer the questionnaire in a browser on this machine, then regrade."""
    import json as _json

    from iamai.questions import latest_assessment
    from iamai.store import SnapshotStore

    config = load_config()
    tenant_id = config.tenant_id(alias)
    artifact, standard = _load_standard(None)
    store = SnapshotStore()
    try:
        latest_assessment(store, alias)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1)

    from iamai.web import create_app

    web_app = create_app(alias=alias, tenant_id=tenant_id, artifact=artifact, store=store,
                         standard=standard)
    typer.echo("The questionnaire wizard is starting. It runs only on this machine.")
    typer.echo(f"  1. Open http://127.0.0.1:{port} in your browser.")
    typer.echo("  2. Answer each question and press Save and continue.")
    typer.echo("  3. When the finished page appears, return here and press Ctrl+C.")
    web_app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    app()
