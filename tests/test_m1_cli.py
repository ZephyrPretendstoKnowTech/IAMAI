"""M1: baseline build and assess CLI contracts, no live network calls."""

import json

import pytest
from typer.testing import CliRunner

import iamai.cli as cli
from iamai.config import Config, save_config

from conftest import APP_ID, TENANT_ID, make_test_client

pytestmark = pytest.mark.m1

runner = CliRunner()

TARGET_TENANT_ID = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
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


def test_baseline_build_freezes_artifact(workspace, mock_graph):
    result = runner.invoke(cli.app, ["baseline", "build", "--yes"])
    assert result.exit_code == 0, result.output
    path = workspace / "baselines" / "baseline-v1.json"
    assert path.exists()
    artifact = json.loads(path.read_text(encoding="utf-8"))
    assert artifact["schemaVersion"] == 2
    assert artifact["builtFrom"]["tenantId"] == TENANT_ID
    assert artifact["controls"]
    assert "frozen" in result.output


def test_baseline_build_says_what_it_will_carry(workspace, mock_graph):
    """This artifact carries the golden tenant's own policy names with no
    pseudonymization pass, unlike a sanitized snapshot -- by design, since
    curation above needs the real names to be useful. That reuse across
    every other engagement graded against it is a choice made on purpose,
    not a silent default (BASELINE-001)."""
    result = runner.invoke(cli.app, ["baseline", "build", "--yes"])
    assert result.exit_code == 0, result.output
    assert "will carry" in result.output
    assert "policy, location and strength name" in result.output


def test_baseline_build_can_be_declined_at_the_last_step(workspace, mock_graph):
    """The confirmation is a real gate, not a notice: declining it must leave
    no artifact behind. Two exclusion GUIDs in the shared fixture each need a
    slot prompt answered (blank accepts the breakGlassAccounts default), then
    "y" accepts the full control inventory, then "n" declines the freeze."""
    result = runner.invoke(cli.app, ["baseline", "build"], input="\n\ny\nn\n")
    assert result.exit_code != 0
    assert not (workspace / "baselines").exists() or not list((workspace / "baselines").glob("*.json"))


def test_baseline_build_warns_about_unbound_identities():
    """SlotResolver.token()'s fallback embeds a raw Entra object id verbatim
    when the operator never binds it to a parameter slot. Unlike a policy
    name, that id can identify a specific person or group, so it gets counted
    and called out by name rather than folded into the generic control count
    (BASELINE-001)."""
    from iamai.cli import _baseline_identity_summary

    artifact = {
        "controls": [
            {
                "id": "cap-001",
                "sourceName": "Core - Allow - MFA for Admins",
                "canonical": {
                    "users": {
                        "include": ["user:20000000-0000-0000-0000-000000000099"],
                        "exclude": ["slot:breakGlassAccounts"],
                    },
                    # An unbound location reference is emitted as "location:",
                    # not "namedLocation:" -- the counter matched the wrong form
                    # and always reported zero (CRYPTO-2-002).
                    "locations": {"include": ["location:50000000-0000-0000-0000-000000000001"]},
                },
            },
            {
                "id": "cap-002",
                "sourceName": "Core - Block - Legacy Authentication",
                "canonical": {"users": {"include": ["role:62e90394-69f5-4237-9190-012177145e10"]}},
            },
            {
                # An unbound IP-based named location embeds the tenant's raw CIDRs.
                "id": "location-001",
                "sourceName": "Head office",
                "canonical": {"surface": "namedLocation", "content": {"cidrs": ["203.0.113.0/24"], "isTrusted": True}},
            },
        ]
    }
    summary = _baseline_identity_summary(artifact)
    assert summary["controls"] == 3
    assert summary["identities"] == 1
    assert summary["locations"] == 1
    assert summary["cidrLocations"] == 1


def test_baseline_build_versions_do_not_overwrite(workspace, mock_graph):
    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    assert (workspace / "baselines" / "baseline-v1.json").exists()
    assert (workspace / "baselines" / "baseline-v2.json").exists()


def test_assess_writes_assessment_and_summary(workspace, mock_graph):
    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    result = runner.invoke(cli.app, ["assess", "golden"])
    assert result.exit_code == 0, result.output
    assessments = list((workspace / "data" / "golden" / "assessments").glob("*-assessment.json"))
    assert len(assessments) == 1
    assessment = json.loads(assessments[0].read_text(encoding="utf-8"))
    assert assessment["alias"] == "golden"
    assert assessment["tenantId"] == TENANT_ID
    assert assessment["controls"]
    assert "FULL" in result.output
    assert "Assessment written to" in result.output


def test_assess_golden_self_is_all_full(workspace, mock_graph):
    """The synthetic golden assessed against its own fresh artifact: the
    same acceptance shape as the live golden run."""
    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    result = runner.invoke(cli.app, ["assess", "golden"])
    assert result.exit_code == 0, result.output
    assessments = list((workspace / "data" / "golden" / "assessments").glob("*-assessment.json"))
    assessment = json.loads(assessments[0].read_text(encoding="utf-8"))
    non_full = [
        (c["controlId"], c["grade"], c["coverageGaps"], c["notes"])
        for c in assessment["controls"] if c["grade"] != "FULL"
    ]
    assert not non_full, non_full
    assert assessment["gradeCounts"].get("UNKNOWN", 0) == 0


def test_without_a_baseline_the_shipped_pack_is_the_standard(workspace, mock_graph):
    """Rewritten deliberately. This used to assert that assess told the reader
    to run 'baseline build'. A baseline is built from a reference tenant
    somebody already trusts, and whoever self hosts this has no such tenant, so
    that was advice they could not take. The pack that ships with the tool is
    the answer for that reader.
    """
    assert cli.DEFAULT_PACK.exists(), "the tool must ship a standard to grade against"
    assert cli._latest_baseline_path() == cli.DEFAULT_PACK

    # It still fails politely, now about the thing that is actually missing.
    result = runner.invoke(cli.app, ["assess", "golden"])
    assert result.exit_code != 0
    message = str(result.exception) + result.output
    assert "collect" in message
    assert "baseline build" not in message
