"""V2-M0: output humanization (SPEC-V2 sections 2 and 7).

The automated acceptance for the milestone: no "gate" in user facing strings
(checkpoint replaces it; schema field names stay), no action string over 300
characters, no list over 8 items rendered inline (longer lists become a
collapsed ListDetail), real calendar dates from the plan's start date, and
role template ids resolved to display names in report gap text. Everything
runs from the sanitized golden fixtures; no live calls.
"""

import copy
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

import iamai.cli as cli

from conftest import freeze_test_baseline
from iamai.grade import assess_snapshot
from iamai.plan import generate_plan
from iamai.report import render_assessment, render_plan
from iamai.store import load_snapshot_data

from test_m1_canon import make_artifact
from test_m4_plan import (  # noqa: F401
    ADMIN_MFA,
    LEGACY_BLOCK,
    TOKEN_PROTECTION,
    UNREGISTERED_USER,
    USER_MFA,
    drop_cap,
    make_answers,
    make_plan,
    pristine_artifact,
    steps_for,
)
from test_m3_questions import workspace  # noqa: F401  (fixture reuse)

pytestmark = pytest.mark.m5

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"

# Word boundary so "investigate" and "delegated" never trip the check.
GATE_WORD = re.compile(r"\bgates?\b", re.IGNORECASE)


@pytest.fixture()
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return copy.deepcopy(data), copy.deepcopy(manifest)


def busy_plan(golden):
    """A plan exercising every step builder: missing CAPs of every kind, an
    unregistered user (TAP, straggler), and an SMS dominant cohort (staged
    strength)."""
    data, manifest = golden
    for name in (USER_MFA, ADMIN_MFA, TOKEN_PROTECTION, LEGACY_BLOCK):
        drop_cap(data, name)
    data["users"].append(dict(UNREGISTERED_USER))
    for row in data["registration_details"]:
        row["userPreferredMethodForSecondaryAuthentication"] = "sms"
    return make_plan(data, manifest)


def _string_values(value):
    """Every string value in a JSON-shaped structure. Keys are schema, not
    user facing text, so they are not yielded (gateId stays by design)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _string_values(child)


# --- Checkpoint replaces gate ---------------------------------------------------


def test_no_gate_word_in_any_user_facing_string(golden):
    plan, _ = busy_plan(golden)
    offenders = [s for s in _string_values(plan) if GATE_WORD.search(s)]
    assert not offenders, offenders
    html = render_plan(plan)
    assert not GATE_WORD.search(html), GATE_WORD.search(html)
    assert "The checkpoints" in html
    assert "Checkpoint to pass" in html


def test_checkpoint_wording_reaches_statements_and_cli_schema_stays(golden):
    plan, _ = busy_plan(golden)
    # Schema field names stay for compatibility.
    assert plan["gates"] and all("gateId" in p for p in plan["phases"])
    enable = next(s for s in plan["steps"] if s["phase"] == 4)
    assert any(p["statement"].startswith("Checkpoint G3 passed") for p in enable["preconditions"])
    assert any(p["statement"].startswith("Checkpoint G2 passed") for p in enable["preconditions"])
    assert "checkpoint" in plan["scopeNote"]


# --- The long list rule ----------------------------------------------------------


def test_no_action_exceeds_300_characters(golden):
    plan, _ = busy_plan(golden)
    for step in plan["steps"]:
        for action in step["actions"]:
            assert len(action) <= 300, (step["id"], len(action), action[:80])


def test_no_action_lists_more_than_8_items_inline(golden):
    plan, _ = busy_plan(golden)
    for step in plan["steps"]:
        for action in step["actions"]:
            trailing = action.rsplit(": ", 1)[-1]
            assert len(trailing.split(", ")) <= 8, (step["id"], action[:120])


def test_admin_role_list_renders_as_collapsed_list(golden):
    plan, _ = busy_plan(golden)
    deploy = next(s for s in steps_for(plan, ADMIN_MFA) if s["phase"] == 3)
    pick = next(a for a in deploy["actions"] if a.startswith("Under Users, select Directory roles"))
    assert "all 133 directory roles in the list" in pick
    detail = next(l for l in deploy["lists"] if l["title"] == "Directory roles this policy covers")
    assert len(detail["items"]) == 133
    assert detail["summary"].startswith("133 directory roles, including")
    # The full list renders collapsed in the HTML, inside a details element.
    html = render_plan(plan)
    assert "<details>" in html
    start = html.find(detail["title"] + ": " + detail["summary"][:40])
    assert start > 0
    assert html.rfind("<details>", 0, start) > html.rfind("</details>", 0, start)


def test_plan_html_caps_long_flat_lists(golden):
    plan, _ = busy_plan(golden)
    plan["unknowns"] = [f"Unknown item number {i} stated honestly." for i in range(1, 13)]
    html = render_plan(plan)
    assert "Show the remaining 4 of 12 items" in html


def test_report_caps_long_lists(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    assessment = assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )
    assessment["unknowns"] = [f"Unknown item number {i} stated honestly." for i in range(1, 13)]
    html = render_assessment(assessment, manifest)
    assert "Show the remaining 4 of 12 items" in html


# --- Role template ids resolve to display names in report gap text ---------------


def test_report_gap_text_resolves_role_template_ids(golden):
    data, manifest = golden
    artifact = pristine_artifact()
    cap = next(c for c in data["conditional_access_policies"] if c["displayName"] == ADMIN_MFA)
    removed = cap["conditions"]["users"]["includeRoles"].pop(0)
    role_names = {
        str(r.get("id", "")).lower(): str(r.get("displayName", ""))
        for r in data["roles"]["roleDefinitions"]
    }
    expected_name = role_names[removed.lower()]
    assessment = assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )
    result = next(c for c in assessment["controls"] if any(
        removed.lower() in g.lower() for g in c["coverageGaps"]
    ))
    assert result["grade"] in ("PARTIAL", "MISSING")
    # The artifact stays raw; the report resolves the token for people.
    html = render_assessment(assessment, manifest, role_names=role_names)
    assert f"the {expected_name} role" in html
    assert f"role:{removed}" not in html


def test_plan_gap_actions_resolve_role_template_ids(golden):
    data, manifest = golden
    cap = next(c for c in data["conditional_access_policies"] if c["displayName"] == ADMIN_MFA)
    removed = cap["conditions"]["users"]["includeRoles"].pop(0)
    role_names = {
        str(r.get("id", "")).lower(): str(r.get("displayName", ""))
        for r in data["roles"]["roleDefinitions"]
    }
    plan, _ = make_plan(data, manifest, artifact=pristine_artifact())
    deploy = next(s for s in steps_for(plan, ADMIN_MFA) if s["phase"] == 3)
    gap_actions = [a for a in deploy["actions"] if a.startswith("Close this gap")]
    assert any(f"the {role_names[removed.lower()]} role" in a for a in gap_actions)
    assert not any(f"role:{removed}" in a for a in gap_actions)


# --- Start date and real calendar dates ------------------------------------------


def test_explicit_start_date_renders_real_dates(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    data["users"].append(dict(UNREGISTERED_USER))
    artifact = None
    from test_m4_plan import enforced_artifact
    artifact = enforced_artifact()
    assessment = assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )
    plan = generate_plan(
        assessment, make_answers(), artifact, data,
        tenant_id="target-tenant", alias="target", start_date="2026-07-20",
    )
    assert plan["startDate"] == "2026-07-20"
    phases = {p["number"]: p for p in plan["phases"]}
    assert phases[1]["dates"] == "Monday 20 July 2026"
    assert phases[2]["dates"] == "Tuesday 21 July 2026 to Thursday 23 July 2026"
    assert phases[4]["dates"] == "Friday 31 July 2026 to Sunday 2 August 2026"
    assert phases[5]["dates"] == "From Monday 3 August 2026"
    # Comms carry the real dates and keep the day count for orientation.
    for text in plan["comms"].values():
        assert "Thursday 30 July 2026 (day 11 of the rollout)" in text \
            or "Friday 31 July 2026 (day 12 of the rollout)" in text
    html = render_plan(plan)
    assert "Rollout starts 2026-07-20" in html
    assert "Monday 20 July 2026" in html


def test_default_start_date_is_today_and_bad_timezone_falls_back(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    from test_m4_plan import enforced_artifact
    artifact = enforced_artifact()
    assessment = assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )
    answers = make_answers(**{
        "report-timezone": ("selectOne", "reportTimezone", "Nowhere/Nonsense", []),
    })
    before = datetime.now(timezone.utc).date().isoformat()
    plan = generate_plan(
        assessment, answers, artifact, data,
        tenant_id="target-tenant", alias="target",
    )
    after = datetime.now(timezone.utc).date().isoformat()
    assert plan["startDate"] in (before, after)


# --- The redesigned plan page ------------------------------------------------------


def test_plan_html_reads_as_a_guide(golden):
    plan, _ = busy_plan(golden)
    html = render_plan(plan)
    assert "How to read this plan" in html
    assert "Step 1 of" in html
    assert 'class="tick"' in html  # print friendly checkboxes
    assert 'class="actions"' in html
    assert "<details>" in html and "<summary>" in html  # progressive disclosure
    assert "Reference: how this step is verified" in html
    assert "<script" not in html.lower()
    assert "—" not in html
    assert "https://" not in html and "http://" not in html


# --- CLI -----------------------------------------------------------------------------


runner = CliRunner()


def _combined_output(result) -> str:
    try:
        return result.output + result.stderr
    except ValueError:
        return result.output


def test_cli_rejects_a_malformed_start_date():
    result = runner.invoke(cli.app, ["plan", "golden", "--start-date", "20-07-2026"])
    assert result.exit_code == 1
    assert "YYYY-MM-DD" in _combined_output(result)


def test_cli_plan_carries_the_start_date(workspace, mock_graph):  # noqa: F811
    import json as _json

    from iamai.questions import generate_questions, latest_assessment
    from iamai.store import SnapshotStore
    from test_m3_questions import _scripted_input

    freeze_test_baseline()
    assert runner.invoke(cli.app, ["assess", "golden"]).exit_code == 0
    store = SnapshotStore()
    assessment = latest_assessment(store, "golden")
    snapshot_dir = store.latest_snapshot("golden")
    data, _ = load_snapshot_data(snapshot_dir)
    questions = generate_questions(assessment, data, snapshot_dir)
    assert runner.invoke(cli.app, ["questions", "golden"], input=_scripted_input(questions)).exit_code == 0

    result = runner.invoke(cli.app, ["plan", "golden", "--start-date", "2026-07-20"])
    assert result.exit_code == 0, _combined_output(result)
    assert "Start date: 2026-07-20" in result.output
    assert "checkpoint G1" in result.output
    plans_dir = store.alias_dir("golden") / "plans"
    plan = _json.loads(next(iter(plans_dir.glob("*-plan.json"))).read_text(encoding="utf-8"))
    assert plan["startDate"] == "2026-07-20"
    assert plan["schemaVersion"] == 2
    html = next(iter(plans_dir.glob("*-plan.html"))).read_text(encoding="utf-8")
    assert not GATE_WORD.search(html)
