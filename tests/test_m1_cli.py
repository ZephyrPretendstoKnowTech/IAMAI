"""M1: the frozen-artifact and assess CLI contracts, no live network calls.

The 'baseline build' command was retired with the golden-tenant concept
(operator decision, 2026-08-17): the standard ships with the tool and there
is no reference-tenant capture. What this file still guards is the invariant
that capture enabled: a tenant graded against the artifact built from its own
snapshot is all FULL with zero UNKNOWN, which is the canonicalization
round-trip proof. conftest.freeze_test_baseline builds that artifact at
library level.
"""

import json

import pytest
from typer.testing import CliRunner

import iamai.cli as cli
from iamai.config import Config, save_config

from conftest import APP_ID, TENANT_ID, freeze_test_baseline, make_test_client

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
            tenants={"golden": TENANT_ID, "target": TARGET_TENANT_ID},
        ),
        tmp_path / "config.yaml",
    )
    monkeypatch.setattr(cli, "make_client", lambda config, tenant_id: make_test_client())
    return tmp_path


def test_frozen_artifact_has_the_documented_shape(workspace, mock_graph):
    path = freeze_test_baseline()
    assert path == workspace / "baselines" / "baseline-v1.json"
    artifact = json.loads(path.read_text(encoding="utf-8"))
    assert artifact["schemaVersion"] == 2
    assert artifact["builtFrom"]["tenantId"] == TENANT_ID
    assert artifact["controls"]


def test_frozen_artifacts_version_and_never_overwrite(workspace, mock_graph):
    freeze_test_baseline()
    freeze_test_baseline()
    assert (workspace / "baselines" / "baseline-v1.json").exists()
    assert (workspace / "baselines" / "baseline-v2.json").exists()


def test_assess_writes_assessment_and_summary(workspace, mock_graph):
    freeze_test_baseline()
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


def test_assess_self_is_all_full(workspace, mock_graph):
    """The synthetic tenant assessed against its own fresh artifact: the
    canonicalization round-trip invariant."""
    freeze_test_baseline()
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
    """The standard ships with the tool: with nothing imported, the bundled
    pack is what grades, and nothing anywhere tells the reader to capture a
    reference tenant (that concept is retired)."""
    assert cli.DEFAULT_PACK.exists(), "the tool must ship a standard to grade against"
    assert cli._latest_baseline_path() == cli.DEFAULT_PACK

    # It still fails politely, now about the thing that is actually missing.
    result = runner.invoke(cli.app, ["assess", "golden"])
    assert result.exit_code != 0
    message = str(result.exception) + result.output
    assert "collect" in message
    assert "baseline build" not in message


def test_the_baseline_group_no_longer_offers_build(workspace):
    result = runner.invoke(cli.app, ["baseline", "build", "--yes"])
    assert result.exit_code != 0
