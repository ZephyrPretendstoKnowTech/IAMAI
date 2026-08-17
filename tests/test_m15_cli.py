"""Stage 2 of the first-run work: --version and iamai doctor.

--version is the natural post-install verification step (the installer runs
it), and doctor folds every check a person would otherwise do by hand into
one command with a per-row next action.
"""

import datetime
import json
from pathlib import Path

import pytest
import respx
from typer.testing import CliRunner

import iamai.cli as cli
from iamai.config import Config, save_config

from conftest import APP_ID, TENANT_ID, make_test_client, register_graph_routes

pytestmark = pytest.mark.m15

runner = CliRunner()


# --- --version -----------------------------------------------------------------


def test_version_flag():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert f"iamai {cli.TOOL_VERSION}" in result.output


def test_version_short_flag():
    result = runner.invoke(cli.app, ["-V"])
    assert result.exit_code == 0
    assert cli.TOOL_VERSION in result.output


def test_version_matches_the_package():
    """Three places carry the version; drift between them means --version
    lies about what is installed."""
    import iamai

    assert cli.TOOL_VERSION == iamai.__version__


# --- doctor --------------------------------------------------------------------


def _write_config(tmp_path: Path) -> Config:
    cert_pem, cert_public = cli.CERT_PEM(), cli.CERT_PUBLIC_PEM()
    cert_pem.parent.mkdir(parents=True, exist_ok=True)
    cli.generate_certificate(cert_pem, cert_public)
    config = Config(
        appId=APP_ID,
        homeTenantId=TENANT_ID,
        certPath=str(cert_pem),
        goldenTenantId=TENANT_ID,
        tenants={"lab": TENANT_ID},
    )
    save_config(config)
    return config


def test_doctor_offline_all_green(tmp_path, monkeypatch):
    _write_config(tmp_path)
    result = runner.invoke(cli.app, ["doctor", "--offline"])
    assert result.exit_code == 0, result.output
    assert "Everything checks out." in result.output
    for check in ("Version", "Python", "Config", "Certificate", "Standard"):
        assert check in result.output
    # Offline means offline: no consent probe, no reachability probe.
    assert "Consent" not in result.output
    assert "Reachable" not in result.output


def test_doctor_without_config_fails_and_says_what_to_run(tmp_path):
    result = runner.invoke(cli.app, ["doctor", "--offline"])
    assert result.exit_code == 1
    assert "FAIL" in result.output
    assert "iamai setup" in result.output


def test_doctor_reports_an_expired_certificate(tmp_path, monkeypatch):
    config = _write_config(tmp_path)
    real_load = cli.x509.load_pem_x509_certificate

    class ExpiredCert:
        not_valid_after_utc = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=3)

    monkeypatch.setattr(cli.x509, "load_pem_x509_certificate", lambda data: ExpiredCert())
    result = runner.invoke(cli.app, ["doctor", "--offline"])
    monkeypatch.setattr(cli.x509, "load_pem_x509_certificate", real_load)
    assert result.exit_code == 1
    assert "Expired" in result.output
    assert "iamai setup" in result.output


def test_doctor_online_probes_consent_per_tenant(tmp_path, monkeypatch, mock_graph):
    _write_config(tmp_path)
    monkeypatch.setattr(cli, "make_client", lambda config, tenant_id: make_test_client())
    # Reachability for the two allowed hosts, mocked so no live call happens.
    mock_graph.get("https://graph.microsoft.com/v1.0/$metadata").respond(status_code=401)
    mock_graph.get(
        "https://login.microsoftonline.com/common/.well-known/openid-configuration"
    ).respond(json={})
    result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "graph.microsoft.com" in result.output
    assert "Consent (lab)" in result.output
    assert "read permissions answer" in result.output


def test_doctor_names_the_missing_permission(tmp_path, monkeypatch):
    _write_config(tmp_path)
    monkeypatch.setattr(cli, "make_client", lambda config, tenant_id: make_test_client())
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        register_graph_routes(router)
        # Reachability fine, but one permission read is denied.
        router.get("https://graph.microsoft.com/v1.0/$metadata").respond(status_code=401)
        router.get(
            "https://login.microsoftonline.com/common/.well-known/openid-configuration"
        ).respond(json={})
        router.get("https://graph.microsoft.com/v1.0/domains").respond(
            status_code=403, json={"error": {"code": "Authorization_RequestDenied",
                                             "message": "denied"}}
        )
        result = runner.invoke(cli.app, ["doctor"])
    assert result.exit_code == 1
    assert "Domain.Read.All" in result.output
    assert "iamai consent lab" in result.output


def test_doctor_reports_the_shipped_standard_when_no_baseline_exists(tmp_path):
    _write_config(tmp_path)
    result = runner.invoke(cli.app, ["doctor", "--offline"])
    assert "ships with the tool" in result.output
