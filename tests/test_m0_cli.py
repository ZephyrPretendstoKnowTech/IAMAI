import filecmp
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import respx
from typer.testing import CliRunner

import iamai.cli as cli
from iamai.config import Config, load_config, save_config

from conftest import APP_ID, TENANT_ID, make_test_client

pytestmark = pytest.mark.m0

runner = CliRunner()

TARGET_TENANT_ID = "22222222-2222-2222-2222-222222222222"
GRAPH_SP_OBJ_ID = "aaaaaaaa-0000-0000-0000-000000000001"
APP_OBJ_ID = "bbbbbbbb-0000-0000-0000-000000000001"
SP_OBJ_ID = "cccccccc-0000-0000-0000-000000000001"
FAKE_PERM_GUID = "dddddddd-0000-0000-0000-000000000001"


SETUP_CLAIMS = {"tid": TENANT_ID, "preferred_username": "admin@contoso.com"}


def _mock_msal_device_code(monkeypatch, browser: bool = True) -> MagicMock:
    """Patch MSAL PublicClientApplication so sign-in returns a fake token.

    browser=True answers the interactive (system browser) call; browser=False
    makes it raise so setup exercises the automatic device code fallback.
    Returns the mock so a test can inspect the scopes setup requested."""
    mock_pub_app = MagicMock()
    token = {"access_token": "fake-setup-token", "id_token_claims": dict(SETUP_CLAIMS)}
    if browser:
        mock_pub_app.acquire_token_interactive.return_value = dict(token)
    else:
        mock_pub_app.acquire_token_interactive.side_effect = RuntimeError("no browser")
    mock_pub_app.initiate_device_flow.return_value = {
        "user_code": "TESTCODE123",
        "verification_uri": "https://microsoft.com/devicelogin",
        "message": "Use code TESTCODE123",
        "interval": 1,
        "expires_in": 300,
    }
    mock_pub_app.acquire_token_by_device_flow.return_value = dict(token)

    import msal as msal_mod
    monkeypatch.setattr(msal_mod, "PublicClientApplication", lambda *a, **kw: mock_pub_app)
    return mock_pub_app


def _register_setup_routes(router: respx.MockRouter) -> None:
    """Register Graph routes for a fresh-create setup run."""
    # Resolve MS Graph SP + appRoles
    router.get(
        f"{cli.GRAPH_BASE}/v1.0/servicePrincipals",
        params__contains={"$filter": f"appId eq '{cli.GRAPH_APP_ID}'"},
    ).respond(json={
        "value": [{
            "id": GRAPH_SP_OBJ_ID,
            "appRoles": [{"value": name, "id": FAKE_PERM_GUID} for name, _ in cli.PERMISSION_TABLE],
        }]
    })

    # No existing IAMAI Collector app
    router.get(
        f"{cli.GRAPH_BASE}/v1.0/applications",
        params__contains={"$filter": "displayName eq 'IAMAI Collector'"},
    ).respond(json={"value": []})

    # Create app
    router.post(f"{cli.GRAPH_BASE}/v1.0/applications").respond(json={
        "appId": APP_ID,
        "id": APP_OBJ_ID,
    })

    # No existing SP for new app
    router.get(
        f"{cli.GRAPH_BASE}/v1.0/servicePrincipals",
        params__contains={"$filter": f"appId eq '{APP_ID}'"},
    ).respond(json={"value": []})

    # Create SP
    router.post(f"{cli.GRAPH_BASE}/v1.0/servicePrincipals").respond(json={"id": SP_OBJ_ID})

    # Note: no appRoleAssignments route. Setup no longer grants consent
    # programmatically, so it never posts there and never needs the scope
    # that would allow it. If setup regressed to granting consent itself,
    # respx's assert_all_mocked would fail this route as unregistered.


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """Isolated working directory with a config and a fake (network-free) client."""
    monkeypatch.chdir(tmp_path)
    save_config(
        Config(
            appId=APP_ID,
            homeTenantId=TENANT_ID,
            certPath="certs/iamai.pem",
            goldenTenantId=TENANT_ID,
            tenants={"golden": TENANT_ID, "target": TARGET_TENANT_ID},
        ),
        tmp_path / "config.yaml",
    )
    monkeypatch.setattr(cli, "make_client", lambda config, tenant_id: make_test_client())
    return tmp_path


def test_the_private_key_file_is_not_created_world_readable(tmp_path):
    """generate_certificate() used to write via Path.write_bytes(), which
    creates the file at the process's default umask -- world-readable (0644)
    on a stock POSIX system. The unencrypted private key is the sole
    credential this tool uses to authenticate to every configured tenant, so
    any other local account on a shared machine could read it (KEY-001)."""
    import os
    import stat

    cert_path = tmp_path / "certs" / "iamai.pem"
    public_path = tmp_path / "certs" / "iamai-cert.pem"
    cli.generate_certificate(cert_path, public_path)

    if os.name != "nt":
        mode = stat.S_IMODE(cert_path.stat().st_mode)
        assert mode == 0o600, oct(mode)
    # The public certificate carries no secret and is fine to leave at the
    # default mode; only the file holding the private key is hardened.
    assert cert_path.exists()
    assert public_path.exists()


def test_require_guid_rejects_a_non_guid():
    """Tenant and application IDs are written into the hand-rolled config.yaml
    emitter, which does no escaping, so a non-GUID (e.g. a newline-bearing
    value) is refused before it can reach that file (INJECT-2-001)."""
    import typer

    assert cli._require_guid("11111111-1111-1111-1111-111111111111", "tenant ID") == \
        "11111111-1111-1111-1111-111111111111"
    for bad in ("not-a-guid", "11111111\ninjected: value", "", "1234"):
        with pytest.raises(typer.Exit):
            cli._require_guid(bad, "tenant ID")


def test_harden_key_file_tightens_an_already_loose_key(tmp_path):
    """The KEY-001 hardening lived only in the new-key path, but setup keeps an
    existing cert without rewriting it, so a key created before the fix stayed
    world-readable and re-running setup never repaired it (SECRETS-2-001).
    _harden_key_file is now applied whenever setup runs."""
    import os
    import stat

    cert_path = tmp_path / "iamai.pem"
    cert_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")
    if os.name != "nt":
        os.chmod(cert_path, 0o644)  # simulate a pre-fix, world-readable key
        assert stat.S_IMODE(cert_path.stat().st_mode) == 0o644

    cli._harden_key_file(cert_path)

    if os.name != "nt":
        assert stat.S_IMODE(cert_path.stat().st_mode) == 0o600, "existing key not re-hardened"


def _write_cert_valid_for(cert_path: Path, days: int) -> None:
    """Write a Collector-shaped cert whose validity ends `days` from now
    (negative = already expired)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IAMAI Collector")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=365))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_an_expired_certificate_stops_with_a_re_auth_instruction(tmp_path):
    """The certificate is deliberately short lived; when it lapses the operator
    should be told to re-run setup, not handed an opaque auth failure from
    deep in a collect (the "then require a re-auth" half of the 180-day cert)."""
    cert_path = tmp_path / "iamai.pem"
    _write_cert_valid_for(cert_path, days=-1)
    import typer

    config = Config(appId=APP_ID, homeTenantId=TENANT_ID, certPath=str(cert_path),
                     goldenTenantId=TENANT_ID, tenants={"golden": TENANT_ID})
    with pytest.raises(typer.Exit):
        cli.make_client(config, TENANT_ID)


def test_a_fresh_certificate_builds_a_client_without_complaint(tmp_path, monkeypatch):
    cert_path = tmp_path / "iamai.pem"
    _write_cert_valid_for(cert_path, days=120)
    config = Config(appId=APP_ID, homeTenantId=TENANT_ID, certPath=str(cert_path),
                     goldenTenantId=TENANT_ID, tenants={"golden": TENANT_ID})
    # Stub the real GraphClient so this exercises only the freshness gate.
    monkeypatch.setattr(cli, "GraphClient", lambda **kw: "client")
    assert cli.make_client(config, TENANT_ID) == "client"


def test_setup_creates_app_and_writes_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "SETUP_CLIENT_ID", "setup-bootstrap-id")
    mock_pub_app = _mock_msal_device_code(monkeypatch)

    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        _register_setup_routes(router)
        # Confirm the echoed tenant, accept the suggested alias.
        result = runner.invoke(cli.app, ["setup"], input="\n\n")

    assert result.exit_code == 0, result.output
    # The tenant came from the sign-in token and was echoed for confirmation;
    # nobody pasted a Directory ID.
    assert "admin@contoso.com" in result.output
    assert TENANT_ID in result.output
    # The scopes were shown before the browser opened, with the read-only frame.
    assert "Application.ReadWrite.OwnedBy" in result.output
    assert "read permission" in result.output
    assert f"{TENANT_ID}/adminconsent?client_id={APP_ID}" in result.output

    # The sign-in requested only the owned-app scope, never the scope that
    # could grant app roles. This is the load-bearing security assertion for
    # the reduced-privilege setup flow.
    requested_scopes = mock_pub_app.acquire_token_interactive.call_args.kwargs["scopes"]
    assert requested_scopes == [f"{cli.GRAPH_BASE}/Application.ReadWrite.OwnedBy"]
    assert not any("AppRoleAssignment" in s for s in requested_scopes)
    assert not any("ReadWrite.All" in s for s in requested_scopes)

    config = load_config(tmp_path / "config.yaml")
    assert config.appId == APP_ID
    assert config.homeTenantId == TENANT_ID
    assert config.setupClientId == "setup-bootstrap-id"
    assert config.tenants == {"contoso": TENANT_ID}
    # The golden tenant is a retired concept; nothing writes it any more.
    assert "goldenTenantId" not in (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert (tmp_path / "certs" / "iamai.pem").exists()
    assert (tmp_path / "certs" / "iamai-cert.pem").exists()
    key_pem = (tmp_path / "certs" / "iamai.pem").read_text()
    assert "PRIVATE KEY" in key_pem and "CERTIFICATE" in key_pem
    assert "PRIVATE KEY" not in (tmp_path / "certs" / "iamai-cert.pem").read_text()


def test_setup_falls_back_to_device_code_without_a_browser(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "SETUP_CLIENT_ID", "setup-bootstrap-id")
    mock_pub_app = _mock_msal_device_code(monkeypatch, browser=False)

    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        _register_setup_routes(router)
        result = runner.invoke(cli.app, ["setup"], input="\n\n")

    assert result.exit_code == 0, result.output
    assert "TESTCODE123" in result.output
    requested_scopes = mock_pub_app.initiate_device_flow.call_args.kwargs["scopes"]
    assert requested_scopes == [f"{cli.GRAPH_BASE}/Application.ReadWrite.OwnedBy"]


def test_setup_refuses_a_mismatched_tenant(tmp_path, monkeypatch):
    """--tenant-id pins the tenant for scripted use; signing in somewhere else
    must stop before anything is created, or a technician with two customer
    accounts registers the app in the wrong client."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "SETUP_CLIENT_ID", "setup-bootstrap-id")
    _mock_msal_device_code(monkeypatch)

    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        _register_setup_routes(router)
        result = runner.invoke(
            cli.app, ["setup", "--tenant-id", TARGET_TENANT_ID], input="\n\n"
        )

    assert result.exit_code == 1
    assert "Nothing was changed" in result.output
    assert not (tmp_path / "config.yaml").exists()


def test_setup_prompts_for_helper_client_id_when_not_configured(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "SETUP_CLIENT_ID", "")
    _mock_msal_device_code(monkeypatch)

    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        _register_setup_routes(router)
        # A non-GUID first, to prove the prompt explains and re-asks rather
        # than crashing; then the real id, the tenant confirm, the alias.
        result = runner.invoke(
            cli.app, ["setup"], input=f"not-a-guid\n{APP_ID}\n\n\n"
        )

    assert result.exit_code == 0, result.output
    assert "one-time sign-in app" in result.output
    assert "not a GUID" in result.output
    assert "read-only permissions" in result.output

    # The helper id is remembered so certificate renewal never re-asks for it.
    config = load_config(tmp_path / "config.yaml")
    assert config.setupClientId == APP_ID


def test_setup_keeps_existing_certificate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "SETUP_CLIENT_ID", "setup-bootstrap-id")
    _mock_msal_device_code(monkeypatch)

    # First run: generate cert
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        _register_setup_routes(router)
        runner.invoke(cli.app, ["setup"], input="\n\n")

    original_cert = (tmp_path / "certs" / "iamai.pem").read_bytes()

    # Second run: the tenant is already configured (no alias prompt) and the
    # cert already exists, so it is kept.
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        _register_setup_routes(router)
        result = runner.invoke(cli.app, ["setup"], input="\n")

    assert result.exit_code == 0, result.output
    assert "already configured as 'contoso'" in result.output
    assert "already exists" in result.output
    assert (tmp_path / "certs" / "iamai.pem").read_bytes() == original_cert


def test_consent_prints_url_for_alias(workspace):
    result = runner.invoke(cli.app, ["consent", "target"])
    assert result.exit_code == 0
    assert (
        "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/"
        f"adminconsent?client_id={APP_ID}" in result.output
    )


def test_verify_prints_full_pass_table(workspace, mock_graph):
    result = runner.invoke(cli.app, ["verify", "golden"])
    assert result.exit_code == 0, result.output
    for permission, _why in cli.PERMISSION_TABLE:
        assert permission in result.output
    assert result.output.count("PASS") == 10
    assert "FAIL" not in result.output
    assert "All permissions verified." in result.output


def test_verify_names_the_failing_scope(workspace, mock_graph):
    mock_graph.get("https://graph.microsoft.com/v1.0/domains").respond(
        403, json={"error": {"code": "Authorization_RequestDenied", "message": "denied"}}
    )
    result = runner.invoke(cli.app, ["verify", "golden"])
    assert result.exit_code == 1
    lines = [line for line in result.output.splitlines() if "Domain.Read.All" in line]
    assert lines and "FAIL" in lines[0]


def test_collect_writes_snapshot_and_summary(workspace, mock_graph):
    result = runner.invoke(cli.app, ["collect", "golden"])
    assert result.exit_code == 0, result.output
    assert "Collection complete." in result.output
    snapshots = [p for p in (workspace / "data" / "golden").iterdir() if p.is_dir()]
    assert len(snapshots) == 1
    assert (snapshots[0] / "manifest.json").exists()
    assert (snapshots[0] / "raw" / "users.json").exists()


def test_two_collects_produce_stable_snapshots(workspace, mock_graph):
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0
    first, second = sorted((workspace / "data" / "golden").iterdir())[:2]
    comparison = filecmp.cmpfiles(
        first / "raw",
        second / "raw",
        common=[p.name for p in (first / "raw").iterdir()],
        shallow=False,
    )
    mismatched_json = [name for name in comparison[1] if name.endswith(".json")]
    # Unchanged tenant: every dataset file identical. (Sign-in jsonl.gz files
    # differ only by gzip mtime header; their decompressed contents match.)
    assert mismatched_json == []
    import gzip

    for name in ("signins_interactive.jsonl.gz", "signins_noninteractive.jsonl.gz"):
        with gzip.open(first / "raw" / name) as a, gzip.open(second / "raw" / name) as b:
            assert a.read() == b.read()


def test_sanitize_produces_clean_copy(workspace, mock_graph):
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0
    result = runner.invoke(cli.app, ["sanitize", "golden"])
    assert result.exit_code == 0, result.output
    assert "Sanitized copy written to" in result.output
    snapshot = sorted((workspace / "data" / "golden").iterdir())[0]
    sanitized_users = json.loads((snapshot / "sanitized" / "users.json").read_text())
    upns = [user["userPrincipalName"] for user in sanitized_users]
    assert all(upn.endswith("@tenant.example") for upn in upns)
    assert (workspace / "data" / "golden" / "pseudo_map.json").exists()


def test_collect_unknown_alias_fails_cleanly(workspace):
    result = runner.invoke(cli.app, ["collect", "nope"])
    assert result.exit_code != 0


def test_purge_requires_exactly_one_mode(workspace, mock_graph):
    """Nothing else in this tool ever removes a collected snapshot
    (RETENTION-001), so what gets deleted must never be a guess: no mode
    selected, or more than one, is refused rather than resolved by picking
    one silently."""
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0

    none_selected = runner.invoke(cli.app, ["purge", "golden", "--yes"])
    assert none_selected.exit_code != 0

    both_selected = runner.invoke(
        cli.app, ["purge", "golden", "--keep-latest", "1", "--all", "--yes"]
    )
    assert both_selected.exit_code != 0

    assert len(list((workspace / "data" / "golden").iterdir())) == 1


def test_purge_unknown_alias_fails_cleanly(workspace):
    result = runner.invoke(cli.app, ["purge", "nope", "--all", "--yes"])
    assert result.exit_code != 0


def test_purge_keep_latest_deletes_the_older_snapshots(workspace, mock_graph):
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0
    before = sorted(p for p in (workspace / "data" / "golden").iterdir() if p.is_dir())
    assert len(before) == 2

    result = runner.invoke(cli.app, ["purge", "golden", "--keep-latest", "1", "--yes"])
    assert result.exit_code == 0, result.output

    after = sorted(p for p in (workspace / "data" / "golden").iterdir() if p.is_dir())
    assert after == before[1:]
    assert "Deleted 1 snapshot" in result.output


def test_purge_declining_the_confirmation_deletes_nothing(workspace, mock_graph):
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0

    result = runner.invoke(
        cli.app, ["purge", "golden", "--keep-latest", "0"], input="n\n"
    )
    assert result.exit_code != 0
    assert "Not deleted" in result.output
    assert len(list((workspace / "data" / "golden").iterdir())) == 2


def test_purge_all_removes_everything_for_the_alias(workspace, mock_graph):
    """The --all case is the "engagement ended" case: not just the
    snapshots, but the assessments, plans, answers file and pseudonym map
    too, since none of it should outlive a client relationship the operator
    has already ended."""
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0
    assert runner.invoke(cli.app, ["sanitize", "golden"]).exit_code == 0
    alias_dir = workspace / "data" / "golden"
    assert (alias_dir / "pseudo_map.json").exists()

    result = runner.invoke(cli.app, ["purge", "golden", "--all", "--yes"])
    assert result.exit_code == 0, result.output
    assert not alias_dir.exists()


def test_sanitize_rejects_an_alias_that_is_not_configured(workspace, mock_graph):
    """Every other alias-taking command checks the alias against the
    configured tenants before touching the filesystem. sanitize() was the one
    exception (AUTHZ-002): it passed the raw argument straight to the
    filesystem with no whitelist check at all."""
    assert runner.invoke(cli.app, ["collect", "golden"]).exit_code == 0
    result = runner.invoke(cli.app, ["sanitize", "not-a-configured-alias"])
    assert result.exit_code != 0


def test_sanitize_rejects_a_path_traversal_alias(workspace):
    """Confirms the same protection holds even for an alias the whitelist
    check alone would not exercise, since alias_dir() itself now refuses to
    build a path outside data/."""
    result = runner.invoke(cli.app, ["sanitize", "../outside"])
    assert result.exit_code != 0
