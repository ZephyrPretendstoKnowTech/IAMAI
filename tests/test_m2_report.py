"""M2: the assessment HTML report (SPEC section 8).

Renders from the sanitized golden fixtures only, no live calls. Checks the
section order the spec fixes, the conservative category status mapping, the
visibility of partial pulls, the naming rules (alias only, stripped
description lines never appear), and the language rules.
"""

import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import iamai.cli as cli
from iamai.config import Config, save_config
from iamai.grade import assess_snapshot
from iamai.report import render_assessment
from iamai.store import load_snapshot_data

from conftest import APP_ID, TENANT_ID, make_test_client
from test_m1_canon import make_artifact

pytestmark = pytest.mark.m2

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"

ADMIN_MFA = "Core - Allow - MFA for Admins"
BLOCK_LEGACY = "Core - Block - Legacy Authentication"


@pytest.fixture()
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return copy.deepcopy(data), copy.deepcopy(manifest)


def render(data, manifest, artifact=None):
    assessment = assess_snapshot(
        artifact or make_artifact(data), data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )
    return render_assessment(assessment, manifest)


def cap_named(data, name):
    return next(c for c in data["conditional_access_policies"] if c["displayName"] == name)


# --- Section order and completeness (SPEC 8: contents in order) ---------------


def test_report_contains_every_section_in_spec_order(golden):
    data, manifest = golden
    html = render(data, manifest)
    sections = [
        "Summary",
        "Access policies",
        "Outside the standard",
        "What this assessment cannot see",
        "Tenant context",
        "not a general policy equivalence engine",
        "print this page to PDF",
    ]
    positions = [html.find(s) for s in sections]
    assert all(p >= 0 for p in positions), list(zip(sections, positions))
    assert positions == sorted(positions), list(zip(sections, positions))


def test_report_shows_alias_collection_window_and_counts(golden):
    data, manifest = golden
    html = render(data, manifest)
    assert "Tenant: target" in html
    assert manifest["collectedAt"] in html
    assert "30 day window" in html
    assert "FULL 20" in html


def test_every_control_appears_with_intent_and_affected_count(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    assessment = assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )
    html = render_assessment(assessment, manifest)
    for control in assessment["controls"]:
        assert f"Control {control['controlId']}" in html
        assert control["intent"], control["controlId"]
        assert control["intent"] in html
    assert "Accounts this applies to:" in html


def _contrast(fg_hex, bg_hex):
    def lum(h):
        h = h.lstrip("#")
        chans = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        chans = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in chans]
        return 0.2126 * chans[0] + 0.7152 * chans[1] + 0.0722 * chans[2]
    a, b = lum(fg_hex), lum(bg_hex)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


def test_theme_text_colours_meet_wcag_aa():
    """The muted secondary colour once sat at 3.5:1 on white, below the 4.5:1
    AA threshold for normal text. Guard every text token so a future palette
    tweak cannot quietly drop below it."""
    import re

    from iamai.theme import BASE_CSS

    tokens = dict(re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", BASE_CSS))
    white = tokens["--surface"]
    for name in ("--ink", "--ink-2", "--muted", "--brand"):
        ratio = _contrast(tokens[name], white)
        assert ratio >= 4.5, f"{name} is {ratio:.2f}:1 on white, below AA 4.5:1"
    # White on the brand fill (buttons, wordmark) must also pass.
    assert _contrast(tokens["--brand-ink"], tokens["--brand"]) >= 4.5


def test_report_uses_the_shared_theme_and_stays_self_contained():
    """Every page draws its look from iamai.theme, inlined so the report opens
    and prints with no outbound request. The theme is injected as a pre-escaped
    value, so a CSS child combinator must survive rather than becoming &gt;."""
    from iamai.theme import BASE_CSS

    data, manifest = load_snapshot_data(FIXTURES)
    assessment = assess_snapshot(
        make_artifact(data), data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )
    html = render_assessment(assessment, manifest)
    # The shared foundation is present and its selectors are not HTML-escaped.
    assert "--brand:" in html
    assert "ol.actions > li" in html and "&gt; li" not in html
    assert 'class="brandbar"' in html
    # Self-contained: no external stylesheet, font, script or image.
    for external in ("<script", "<link ", "@import", "http://", "https://"):
        assert external not in html, external
    # The theme constant itself carries no external reference.
    assert "http" not in BASE_CSS and "url(" not in BASE_CSS


# --- Category status is conservative ------------------------------------------


def test_golden_self_report_is_all_green(golden):
    data, manifest = golden
    html = render(data, manifest)
    assert "Meets the standard" in html
    assert "Needs attention" not in html
    assert "Protection missing" not in html
    assert "Some data is incomplete" not in html


def test_deleted_policy_turns_its_category_red(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    data["conditional_access_policies"] = [
        c for c in data["conditional_access_policies"] if c["displayName"] != BLOCK_LEGACY
    ]
    html = render(data, manifest, artifact)
    assert "Protection missing" in html


def test_partial_pull_surfaces_visibly(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    manifest["complete"] = False
    for record in manifest["datasets"]:
        if record["dataset"] == "conditional_access_policies":
            record["complete"] = False
    html = render(data, manifest, artifact)
    assert "Some data is incomplete" in html
    assert "graded UNKNOWN" in html
    assert "Needs attention" in html
    assert "collector pull incomplete" in html


# --- Surplus --------------------------------------------------------------------


def test_surplus_listed_and_never_penalized(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    extra = copy.deepcopy(cap_named(data, ADMIN_MFA))
    extra["id"] = "99999999-9999-9999-9999-999999999999"
    extra["displayName"] = "Custom app lockdown"
    extra["conditions"]["applications"]["includeApplications"] = [
        "88888888-8888-8888-8888-888888888888"
    ]
    data["conditional_access_policies"].append(extra)
    html = render(data, manifest, artifact)
    assert "Custom app lockdown" in html
    assert "never" in html and "penalized" in html
    assert "Protection missing" not in html


# --- Naming and language rules ---------------------------------------------------


def test_stripped_description_lines_never_appear(golden):
    data, manifest = golden
    cap = cap_named(data, ADMIN_MFA)
    cap["description"] = (
        "Tag: BASELINE-CORE-XYZZY\n"
        "Version: 3\n"
        "Date: 2026-01-01\n"
        "Owner: Jane Operator\n"
        "Purpose: Require strong sign in for administrators.\n"
        "Scope: All admin role holders.\n"
        "Rationale: Admin accounts are the highest value target."
    )
    artifact = make_artifact(data)
    html = render(data, manifest, artifact)
    assert "Require strong sign in for administrators." in html
    assert "Admin accounts are the highest value target." in html
    for forbidden in ("BASELINE-CORE-XYZZY", "Jane Operator", "Version: 3"):
        assert forbidden not in json.dumps(artifact)
        assert forbidden not in html


def test_tenant_ids_never_appear_only_the_alias(golden):
    data, manifest = golden
    html = render(data, manifest)
    assert "Tenant: target" in html
    assert "target-tenant" not in html
    assert manifest["tenantId"] not in html
    assert "the standard" in html


def test_language_rules_and_self_containment(golden):
    data, manifest = golden
    html = render(data, manifest)
    assert "—" not in html  # no em dashes anywhere
    assert "<script" not in html.lower()
    assert "http://" not in html and "https://" not in html


# --- CLI contract: assess writes assessment + report -----------------------------


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


def test_assess_writes_html_report(workspace, mock_graph):
    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    result = runner.invoke(cli.app, ["assess", "golden"])
    assert result.exit_code == 0, result.output
    assert "Report written to" in result.output
    reports = list((workspace / "data" / "golden" / "assessments").glob("*-report.html"))
    assert len(reports) == 1
    html = reports[0].read_text(encoding="utf-8")
    assert "Identity security assessment" in html
    assert "Tenant: golden" in html
    assert "Meets the standard" in html
