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


# --- Stage 3: the read-only promise is mechanical, and grades name their standard


def test_the_collector_permission_set_passes_the_read_only_assertion():
    cli.assert_permissions_read_only(cli.PERMISSION_NAMES)


@pytest.mark.parametrize("bad", [
    "Mail.ReadWrite",
    "Application.ReadWrite.All",
    "User.Invite.All",
    "Directory.AccessAsUser.All",
    "Mail.Send",
    "Sites.Manage.All",
    "Policy.Read.All,Directory.Write.All".split(",")[1],
])
def test_the_read_only_assertion_refuses_write_shaped_permissions(bad):
    with pytest.raises(RuntimeError):
        cli.assert_permissions_read_only([bad])


def test_the_read_only_assertion_is_segment_aware():
    """RoleManagement contains the word Manage; the resource name must not
    trip the check, only an actual write action segment may."""
    cli.assert_permissions_read_only(["RoleManagement.Read.Directory"])


def test_the_shipped_standard_descriptor_names_itself():
    artifact, descriptor = cli._load_standard(None)
    assert descriptor["source"] == "shipped"
    assert "ships with this tool" in descriptor["name"]
    assert descriptor["controls"] == len(artifact["controls"])
    assert descriptor["version"], "the shipped standard must carry a version"


def test_the_report_states_which_standard_graded_it():
    from iamai.report import render_assessment

    assessment = {
        "alias": "lab", "generatedAt": "2026-08-17T00:00:00Z",
        "gradeCounts": {}, "controls": [],
        "standard": {"name": "the standard that ships with this tool",
                     "version": "v1", "controls": 37, "source": "shipped"},
    }
    html = render_assessment(assessment)
    assert "Graded against the standard that ships with this tool" in html
    assert "version v1" in html


# --- Stage 4: the JSON contract carries answers, sections, and provenance ------


def test_every_shipped_surface_has_a_plain_language_section():
    """A camelCase surface name reaching a reader is the exact defect the
    operator flagged in the report summary; the map must cover every surface
    either shipped pack uses, and every one the engine can emit."""
    from iamai.grade import SECTION_LABELS

    packs_dir = Path(__file__).parents[1] / "src" / "iamai" / "packs"
    for pack_file in packs_dir.glob("*.json"):
        pack = json.loads(pack_file.read_text(encoding="utf-8"))
        for control in pack["controls"]:
            surface = control["surface"]
            assert surface in SECTION_LABELS, f"{pack_file.name}: {surface} has no section label"
            label = SECTION_LABELS[surface]
            assert label[0].isupper() and "_" not in label
            # A human name, not an identifier: no camelCase.
            assert not any(c.isupper() for c in label[1:].replace(" ", "x")[1:]) or " " in label


def test_control_ids_are_unique_and_stable_shaped():
    packs_dir = Path(__file__).parents[1] / "src" / "iamai" / "packs"
    for pack_file in packs_dir.glob("*.json"):
        pack = json.loads(pack_file.read_text(encoding="utf-8"))
        ids = [c["id"] for c in pack["controls"]]
        assert len(ids) == len(set(ids)), f"duplicate control ids in {pack_file.name}"
        for control_id in ids:
            assert control_id == control_id.strip() and " " not in control_id


def test_the_assessment_carries_answers_sections_and_provenance(tmp_path, monkeypatch, mock_graph):
    from typer.testing import CliRunner

    monkeypatch.chdir(tmp_path)
    _write_config(tmp_path)
    monkeypatch.setattr(cli, "make_client", lambda config, tenant_id: make_test_client())
    local_runner = CliRunner()
    result = local_runner.invoke(cli.app, ["collect", "lab"])
    assert result.exit_code == 0, result.output
    result = local_runner.invoke(cli.app, ["assess", "lab"])
    assert result.exit_code == 0, result.output

    assessments = list((tmp_path / "data" / "lab" / "assessments").glob("*-assessment.json"))
    assessment = json.loads(assessments[0].read_text(encoding="utf-8"))
    # The contract additions (work order part 5.1), all additive to version 1.
    assert assessment["standard"]["source"] == "shipped"
    assert isinstance(assessment["answers"], list)  # empty until the wizard runs
    prov = assessment["dataProvenance"]
    assert prov["sanitized"] is False
    assert prov["snapshot"] and prov["collectedAt"]
    for control in assessment["controls"]:
        assert control["section"], control["controlId"]
        assert "Uppercase" not in control["section"]

    # And the record still validates against the published schema, using the
    # same minimal validator the artifact-schema suite uses.
    from test_artifact_schema import validate

    schema = json.loads((Path(__file__).parents[1] / "schemas" / "assessment.schema.json")
                        .read_text(encoding="utf-8"))
    validate(assessment, schema, defs=schema.get("$defs"))
