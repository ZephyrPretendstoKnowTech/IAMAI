"""IAMAI command line interface.

Commands are idempotent and file based. All user-facing text is plain
language for a reader with no IAM experience: numbered single-action steps,
no jargon without a one-line explanation.
"""

from __future__ import annotations

import base64
import datetime
import os
import re
import subprocess
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

def _acquire_setup_token(setup_client_id: str, tenant_id: str) -> str:
    """Device code flow against the golden tenant. Returns an access token."""
    import msal

    pub_app = msal.PublicClientApplication(
        client_id=setup_client_id,
        authority=f"{LOGIN_BASE}/{tenant_id}",
    )
    flow = pub_app.initiate_device_flow(
        scopes=[
            # OwnedBy, not All: this lets setup create the Collector app and
            # its service principal and manage only that app, never rewrite
            # any other app in the tenant (verified against Microsoft Graph
            # permissions reference, ASSUMPTIONS.md note 35). AppRoleAssignment
            # .ReadWrite.All is deliberately NOT requested: it is the only
            # scope that grants app roles and Microsoft warns it lets an app
            # grant privileges to itself, so instead of granting consent
            # programmatically, setup prints the admin-consent URL for the
            # signed-in Global Administrator to approve read-only access
            # through Microsoft's own screen -- the same flow already used for
            # a second tenant.
            f"{GRAPH_BASE}/Application.ReadWrite.OwnedBy",
        ]
    )
    if "user_code" not in flow:
        raise typer.Exit(
            typer.echo(f"Failed to start authentication: {flow.get('error_description', 'unknown error')}", err=True)
            or 1
        )
    typer.echo("")
    typer.echo("Authenticate to create the app registration:")
    typer.echo(f"  1. Open this URL: {flow['verification_uri']}")
    typer.echo(f"  2. Enter this code: {flow['user_code']}")
    typer.echo("  3. Sign in as a Global Administrator of the golden tenant.")
    typer.echo("  4. Return here when done.")
    typer.echo("")
    typer.echo("Waiting for authentication...", nl=False)
    result = pub_app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        typer.echo(" failed.", err=True)
        raise typer.Exit(1)
    typer.echo(" done.")
    return result["access_token"]


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

    Fetches the Microsoft Graph service principal from the golden tenant and
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

@app.command()
def setup() -> None:
    """Create the IAMAI Collector app registration via Graph and write config."""
    typer.echo("IAMAI setup")
    typer.echo("")

    golden_tenant_id = _require_guid(typer.prompt("Golden tenant ID (Directory ID)"), "tenant ID")
    golden_alias = typer.prompt("Alias for the golden tenant", default="golden")
    target_alias = typer.prompt("Alias for the target tenant (leave blank to add later)", default="")
    target_tenant_id = ""
    if target_alias.strip():
        target_tenant_id = _require_guid(
            typer.prompt(f"Tenant ID for '{target_alias.strip()}'"), "tenant ID"
        )

    cert_pem, cert_public_pem = CERT_PEM(), CERT_PUBLIC_PEM()
    cert_pem.parent.mkdir(parents=True, exist_ok=True)
    if cert_pem.exists():
        typer.echo(f"Certificate already exists at {cert_pem}, keeping it.")
        # Harden it even though we did not just create it: a key generated
        # before this hardening existed would otherwise stay world-readable,
        # since this branch never rewrites it (SECRETS-2-001).
        _harden_key_file(cert_pem)
    else:
        generate_certificate(cert_pem, cert_public_pem)
        typer.echo(f"Generated a new self-signed certificate (valid {CERT_LIFETIME_DAYS} days).")

    cert_obj = x509.load_pem_x509_certificate(cert_public_pem.read_bytes())
    cert_der_b64 = base64.b64encode(cert_obj.public_bytes(serialization.Encoding.DER)).decode("ascii")

    setup_client_id = SETUP_CLIENT_ID
    if not setup_client_id:
        typer.echo("")
        typer.echo("IAMAI Setup bootstrapper app not yet registered. You only do this once.")
        typer.echo("")
        typer.echo("Fast path. If you have the Azure CLI and are signed in to the golden")
        typer.echo("tenant as a Global Administrator (az login), one command creates it and")
        typer.echo("prints the client ID to paste below:")
        typer.echo("")
        typer.echo('  az ad app create --display-name "IAMAI Setup" '
                   "--sign-in-audience AzureADMultipleOrgs "
                   "--is-fallback-public-client true --query appId -o tsv")
        typer.echo("")
        typer.echo("Manual path. About two minutes in the portal:")
        typer.echo("")
        typer.echo("  1. Open, signed in as a Global Administrator of the golden tenant:")
        typer.echo("     https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade")
        typer.echo("     (or Entra ID > App registrations > New registration).")
        typer.echo('  2. Name: "IAMAI Setup"  |  Supported accounts: Any organizational directory '
                   "(multitenant)  |  Register.")
        typer.echo("  3. Authentication tab > Advanced settings > Allow public client flows: Yes > Save.")
        typer.echo("  4. Copy the Application (client) ID from the Overview page.")
        typer.echo("")
        setup_client_id = typer.prompt("IAMAI Setup client ID")
        if not setup_client_id.strip():
            typer.echo("No client ID entered. Run setup again when ready.", err=True)
            raise typer.Exit(1)

    token = _acquire_setup_token(setup_client_id.strip(), golden_tenant_id)

    typer.echo("Resolving permission GUIDs from Microsoft Graph...")
    perm_guids = _resolve_permission_guids(token)
    resource_access = [{"id": guid, "type": "Role"} for guid in perm_guids]

    typer.echo("Creating app registration...")
    app_id, _app_obj_id = _get_or_create_app(token, cert_der_b64, resource_access)
    # Graph assigns this, so it is trusted, but config.yaml is emitted by a
    # hand-rolled writer that does not escape values; validating it is a
    # GUID keeps anything but a GUID out of that file (INJECT-2-001).
    app_id = _require_guid(app_id, "application ID from Graph")

    typer.echo("Creating service principal in golden tenant...")
    _get_or_create_sp(token, app_id)

    tenants: dict[str, str] = {golden_alias: golden_tenant_id}
    if target_alias.strip() and target_tenant_id.strip():
        tenants[target_alias.strip()] = target_tenant_id.strip()

    config = Config(
        appId=app_id,
        homeTenantId=golden_tenant_id,
        certPath=str(cert_pem),
        goldenTenantId=golden_tenant_id,
        tenants=tenants,
    )
    config_path = save_config(config)
    typer.echo("")
    typer.echo(f"Config written to {config_path}.")
    typer.echo("")

    # The app exists but holds no consent yet. The signed-in administrator
    # approves its read-only permissions through Microsoft's own screen, so
    # setup never needed a scope that could grant app roles itself.
    golden_url = CONSENT_URL_TEMPLATE.format(tenantId=golden_tenant_id, appId=app_id)
    typer.echo("One step left: grant the read-only permissions.")
    typer.echo(f"  1. Open this link, still signed in as a Global Administrator: {golden_url}")
    typer.echo("  2. Review the list (every permission is a read permission) and Accept.")
    typer.echo(f"  3. Confirm it worked: iamai verify {golden_alias}")

    if target_alias.strip() and target_tenant_id.strip():
        url = CONSENT_URL_TEMPLATE.format(tenantId=target_tenant_id.strip(), appId=app_id)
        typer.echo("")
        typer.echo(f"To consent the target tenant '{target_alias.strip()}', ask its administrator to open:")
        typer.echo(f"  {url}")
    else:
        typer.echo("")
        typer.echo("To add a target tenant later, run: iamai consent <alias>")

    typer.echo("")
    typer.echo("The app is registered. It cannot read anything until the consent "
                "link above is accepted.")


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
        # A baseline built from this tenant lives under baselines/, outside the
        # alias dir, so it is not removed here. It can carry the tenant's policy
        # names and, for unbound IP locations, its network ranges, so point at
        # it rather than deleting a shared standard on the operator's behalf
        # (CRYPTO-2-004).
        try:
            is_golden = alias == _golden_alias(config)
        except typer.BadParameter:
            is_golden = False
        if is_golden:
            baselines = sorted(_baselines_dir().glob("baseline-v*.json")) if _baselines_dir().exists() else []
            if baselines:
                typer.echo(
                    f"Note: {len(baselines)} baseline artifact(s) built from this "
                    f"tenant remain under {_baselines_dir()}/. Delete them by hand if "
                    "this tenant's data should not persist there."
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
    help="Build and manage the baseline artifact.",
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


def _golden_alias(config: Config) -> str:
    for alias, tenant_id in config.tenants.items():
        if tenant_id == config.goldenTenantId:
            return alias
    raise typer.BadParameter(
        "No configured alias points at goldenTenantId. Add the golden tenant to config.yaml."
    )


def _next_baseline_path() -> Path:
    _baselines_dir().mkdir(parents=True, exist_ok=True)
    version = 1
    while (_baselines_dir() / f"baseline-v{version}.json").exists():
        version += 1
    return _baselines_dir() / f"baseline-v{version}.json"


def _latest_baseline_path() -> Path:
    candidates = sorted(
        _baselines_dir().glob("baseline-v*.json"),
        key=lambda p: int(p.stem.split("-v")[-1]) if p.stem.split("-v")[-1].isdigit() else 0,
    )
    if not candidates:
        # A baseline is built from a reference tenant somebody already trusts.
        # Whoever self hosts this has no such tenant, and telling them to build
        # one is advice they cannot take, so fall back to the standard that
        # ships with the tool. The pack is the default answer for that reader;
        # the baseline is the option for somebody who has a tenant to copy.
        if DEFAULT_PACK.is_file():
            return DEFAULT_PACK
        raise FileNotFoundError(
            "No standard to grade against. Either pass --pack with a standard "
            "pack from packs/, or build one from a reference tenant you trust "
            "with 'iamai baseline build'."
        )
    return candidates[-1]


_UNBOUND_IDENTITY_RE = re.compile(r'"(user|group):([0-9a-fA-F-]{36})"')
# Unbound named-location references are emitted as "location:<guid>", not
# "namedLocation:" (canon.py's _canonical_locations); the earlier pattern here
# matched a form the artifact never contains, so the location count was always
# zero (CRYPTO-2-002).
_UNBOUND_LOCATION_RE = re.compile(r'"location:([0-9a-fA-F-]{36})"')


def _baseline_identity_summary(artifact: dict) -> dict:
    """What tenant-specific data a frozen baseline would carry.

    A baseline carries the golden tenant's own policy, location and strength
    names with no pseudonymization pass -- unlike a sanitized snapshot, this
    is by design, because those names are shown to the operator during
    curation, right here in this command, before the artifact exists to
    sanitize. Pseudonymizing them would break the thing that lets an operator
    decide what they are including. What is worth a warning is different: an
    include or exclude list the operator never bound to a parameter slot
    embeds the raw Entra object id verbatim (SlotResolver.token()'s fallback),
    and unlike a policy name, that id can name a specific person; and an
    unbound IP-based named location embeds the tenant's raw CIDR ranges
    (BASELINE-001, CRYPTO-2-002).
    """
    import json as _json

    blob = _json.dumps(artifact)
    identities = {m.group(0) for m in _UNBOUND_IDENTITY_RE.finditer(blob)}
    locations = {m.group(0) for m in _UNBOUND_LOCATION_RE.finditer(blob)}
    # An unbound ipNamedLocation canonicalizes to {"cidrs": [...], ...}; count
    # the controls that carry one, so the operator is told the artifact holds
    # the tenant's real network ranges.
    cidr_locations = sum(
        1 for control in artifact.get("controls", [])
        if isinstance((control.get("canonical") or {}).get("content"), dict)
        and "cidrs" in control["canonical"]["content"]
    )
    return {
        "controls": len(artifact.get("controls", [])),
        "identities": len(identities),
        "locations": len(locations),
        "cidrLocations": cidr_locations,
    }


@baseline_app.command("build")
def baseline_build(
    days: int = typer.Option(30, "--days", help="How many days of sign-in logs to pull."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Accept the full inventory and default slot bindings without prompting."),
) -> None:
    """Pull the golden tenant, curate the inventory, freeze the baseline artifact."""
    import json as _json

    from iamai.canon import build_artifact
    from iamai.collectors import run_all
    from iamai.store import SnapshotStore, load_snapshot_data

    config = load_config()
    alias = _golden_alias(config)
    typer.echo(f"Collecting the golden tenant ('{alias}') to build the baseline.")
    client = make_client(config, config.goldenTenantId)
    store = SnapshotStore()
    writer = store.new_snapshot(alias)
    manifest = run_all(client, writer, alias, days=days)
    if not manifest.complete:
        typer.echo("The collection was incomplete. A baseline must be built from a complete pull.", err=True)
        raise typer.Exit(code=1)
    data, _ = load_snapshot_data(writer.snapshot_dir)

    # Golden-side policy exclusion GUIDs bind to parameter slots. Default:
    # they are the standard's break-glass exclusions.
    exclusion_guids: list[str] = []
    for cap in data.get("conditional_access_policies") or []:
        users = (cap.get("conditions") or {}).get("users") or {}
        for guid in (users.get("excludeGroups") or []) + (users.get("excludeUsers") or []):
            if guid not in exclusion_guids:
                exclusion_guids.append(guid)
    slot_bindings: dict[str, list[str]] = {"breakGlassAccounts": []}
    groups_data = data.get("groups") or {}
    group_list = groups_data.get("groups", []) if isinstance(groups_data, dict) else groups_data
    group_names = {
        str(g.get("id", "")).lower(): str(g.get("displayName", ""))
        for g in group_list
        if isinstance(g, dict)
    }
    for guid in exclusion_guids:
        label = group_names.get(guid.lower(), guid)
        if yes:
            slot_bindings["breakGlassAccounts"].append(guid)
            continue
        slot = typer.prompt(
            f"The golden tenant excludes '{label}' from its policies. Which parameter slot is it? "
            "(breakGlassAccounts, serviceAccounts, pilotGroups)",
            default="breakGlassAccounts",
        )
        slot_bindings.setdefault(slot.strip(), []).append(guid)

    artifact = build_artifact(
        data,
        tenant_id=config.goldenTenantId,
        snapshot=writer.snapshot_dir.name,
        tool_version=TOOL_VERSION,
        slot_bindings=slot_bindings,
    )

    typer.echo("")
    typer.echo("Baseline inventory:")
    for control in artifact["controls"]:
        typer.echo(f"  {control['id']:<24} {control['surface']:<24} {control['sourceName']}")
    excluded: set[str] = set()
    if not yes and not typer.confirm(f"Include all {len(artifact['controls'])} controls?", default=True):
        for control in list(artifact["controls"]):
            if not typer.confirm(f"  Include {control['id']} ({control['sourceName']})?", default=True):
                excluded.add(control["id"])
        artifact = build_artifact(
            data,
            tenant_id=config.goldenTenantId,
            snapshot=writer.snapshot_dir.name,
            tool_version=TOOL_VERSION,
            slot_bindings=slot_bindings,
            exclude_control_ids=excluded,
        )

    # This artifact carries the golden tenant's own policy, location and
    # strength names with no pseudonymization pass, unlike a sanitized
    # snapshot -- by design, since those names were just shown above to let
    # the operator decide what to include. It stays off the public repository
    # (baselines/ is gitignored) but is reused across every other tenant this
    # is graded against, on the same machine. That reuse across engagements
    # is a real, if narrower, exposure, so it is a choice the operator makes
    # on purpose here rather than a silent default (BASELINE-001).
    summary = _baseline_identity_summary(artifact)
    typer.echo("")
    typer.echo(
        f"This baseline will carry {summary['controls']} policy, location and "
        "strength name(s) from the golden tenant. It never leaves this machine "
        "on its own, but it will be reused for every other tenant graded "
        "against it."
    )
    if summary["identities"]:
        typer.echo(
            f"It also carries {summary['identities']} user or group id from the "
            "golden tenant's own policies that was not mapped to a parameter "
            "slot (breakGlassAccounts, serviceAccounts, pilotGroups) during "
            "curation. Unlike a policy name, this can identify a specific person "
            "or group. Re-run and bind it to a slot if that matters here."
        )
    if summary["locations"]:
        typer.echo(
            f"It also carries {summary['locations']} named location id from the "
            "golden tenant that was not mapped to a parameter slot."
        )
    if summary["cidrLocations"]:
        typer.echo(
            f"It also carries {summary['cidrLocations']} IP-based named "
            "location(s) with the golden tenant's raw network ranges (CIDRs). "
            "Bind them to a slot during curation to keep the tenant's addresses "
            "out of a baseline that travels to other engagements."
        )
    if not yes and not typer.confirm("Freeze this baseline?", default=True):
        typer.echo("Not written.")
        raise typer.Exit(code=1)

    path = _next_baseline_path()
    path.write_text(_json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    typer.echo("")
    typer.echo(f"Baseline artifact frozen: {path} ({len(artifact['controls'])} controls).")
    typer.echo("Run 'iamai assess <alias>' to grade a tenant against it.")


@baseline_app.command("import")
def baseline_import(
    pack_path: Path = typer.Argument(..., help="Path to a standard pack JSON file (see packs/)."),
) -> None:
    """Validate an authored standard pack and freeze it as the active baseline.

    A pack is tenant free: it needs no golden collect. The import runs the
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
        help="Grade against a standard pack (see packs/) instead of a baseline "
             "built from a reference tenant.",
        exists=True,
        dir_okay=False,
    ),
) -> None:
    """Grade the latest snapshot against a standard and write assessment.json.

    Two kinds of standard exist and they are graded identically. A pack is
    written once and shipped with the tool, which is what a self hosting user
    gets. A baseline is derived from a reference tenant, which is what someone
    with a tenant they already trust can build for themselves.
    """
    import json as _json

    from iamai.grade import UNKNOWN
    from iamai.questions import assess_with_answers
    from iamai.store import SnapshotStore

    config = load_config()
    baseline_path = Path(pack) if pack else _latest_baseline_path()
    artifact = _json.loads(baseline_path.read_text(encoding="utf-8"))
    store = SnapshotStore()

    assessment, out_path, report_path, answer_count = assess_with_answers(
        alias, config.tenant_id(alias), artifact, store
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
    baseline_path = _latest_baseline_path()
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

    regraded, out_path, report_path, _ = assess_with_answers(alias, tenant_id, artifact, store)
    changes = grade_changes(assessment, regraded)
    typer.echo("")
    typer.echo("Answers saved. The assessment was regraded with them.")
    if changes:
        for change in changes:
            typer.echo(f"  Control {change['controlId']} moved from {change['from']} to {change['to']}.")
    else:
        typer.echo("  No grades changed. The answers are saved and will be used by the plan.")
    typer.echo("")
    _echo_assessment(regraded, baseline_path.name)
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
    baseline_path = _latest_baseline_path()
    artifact = _json.loads(baseline_path.read_text(encoding="utf-8"))
    store = SnapshotStore()
    try:
        latest_assessment(store, alias)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1)

    from iamai.web import create_app

    web_app = create_app(alias=alias, tenant_id=tenant_id, artifact=artifact, store=store)
    typer.echo("The questionnaire wizard is starting. It runs only on this machine.")
    typer.echo(f"  1. Open http://127.0.0.1:{port} in your browser.")
    typer.echo("  2. Answer each question and press Save and continue.")
    typer.echo("  3. When the finished page appears, return here and press Ctrl+C.")
    web_app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    app()
