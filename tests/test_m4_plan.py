"""M4: the plan generator (SPEC section 10).

The acceptance core per the kickoff: day 1 is break glass, every gate
references a checkable query, every step card validates against the schema
with every mandatory field, and the service principal preflight appears on
any app targeted policy step. Plus the fixed sequencing rules: report-only
before enforced, registration before enforcement with the cohort split,
legacy auth inventory before any block, and the weakest method never
codified. Everything runs from the sanitized golden fixtures; no live calls.
"""

import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import iamai.cli as cli
from iamai.grade import assess_snapshot
from iamai.plan import StepCard, generate_plan
from iamai.questions import Answer, AnswersFile
from iamai.report import render_plan
from iamai.store import load_snapshot_data

from test_m1_canon import make_artifact
from test_m3_questions import workspace  # noqa: F401  (fixture reuse)

pytestmark = pytest.mark.m4

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"

ADMIN_MFA = "Core - Allow - MFA for Admins"
USER_MFA = "Core - Allow - MFA for Internal Users"
TOKEN_PROTECTION = "Core - Require - Token Protection (Windows)"
LEGACY_BLOCK = "Core - Block - Legacy Authentication"

BREAK_GLASS_GUID = "5137fe56-b084-441a-a61b-0dcff4e618d8"
BREAK_GLASS_LABEL = "breakglass@tenant.example"
UNREGISTERED_USER = {
    "id": "40000000-0000-0000-0000-000000000004",
    "userPrincipalName": "user9@tenant.example",
    "accountEnabled": True,
    "userType": "Member",
}


@pytest.fixture()
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return copy.deepcopy(data), copy.deepcopy(manifest)


def drop_cap(data, name):
    data["conditional_access_policies"] = [
        c for c in data["conditional_access_policies"] if c["displayName"] != name
    ]


def pristine_artifact():
    """The baseline built from the unmutated golden fixture, so policies
    dropped from the target data still exist as baseline controls."""
    data, _ = load_snapshot_data(FIXTURES)
    return make_artifact(copy.deepcopy(data))


def enforced_artifact():
    """Pristine artifact whose conditional access controls require the
    enabled state, so enable steps are generated (the golden capture is
    report-only)."""
    artifact = pristine_artifact()
    for control in artifact["controls"]:
        if control["surface"] == "conditionalAccess":
            control["requiredState"] = "enabled"
    return artifact


def make_answers(**overrides) -> AnswersFile:
    answers = AnswersFile(tenantId="target-tenant", alias="target")
    defaults = {
        "break-glass": ("selectAccounts", "breakGlassAccounts", [BREAK_GLASS_GUID], [BREAK_GLASS_LABEL]),
        "trusted-locations": ("selectLocations", "trustedLocations", ["203.0.113.5"], ["203.0.113.5"]),
        "license-tier": ("singleChoice", "licenseTier", "BusinessPremium", ["Business Premium"]),
        "report-timezone": ("selectOne", "reportTimezone", "UTC", []),
        "special-handling": ("freeText", "specialHandling", "", []),
    }
    defaults.update(overrides)
    for qid, (atype, binds, value, labels) in defaults.items():
        answers.answers[qid] = Answer(
            questionId=qid, answerType=atype, bindsTo=binds,
            value=value, labels=labels, answeredAt="2026-07-06T00:00:00Z",
        )
    return answers


def make_plan(data, manifest, artifact=None, answers=None):
    artifact = artifact or enforced_artifact()
    assessment = assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )
    return generate_plan(
        assessment, answers or make_answers(), artifact, data,
        tenant_id="target-tenant", alias="target",
    ), assessment


def steps_for(plan, control_source_name):
    return [s for s in plan["steps"] if control_source_name in s["title"]]


# --- The acceptance core ---------------------------------------------------------


def test_day_one_is_break_glass_and_nothing_ships_before_it(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    plan, _ = make_plan(data, manifest)
    first = plan["steps"][0]
    assert first["phase"] == 1
    assert "break glass" in first["title"].lower()
    assert first["riskClass"] == "high"
    assert all(step["phase"] >= 2 for step in plan["steps"][1:])
    phase_one = plan["phases"][0]
    assert phase_one["days"] == "Day 1"
    assert phase_one["gateId"] == "G1"
    # The confirmed accounts flow into the step.
    assert BREAK_GLASS_LABEL in " ".join(first["actions"])


def test_every_step_card_has_every_mandatory_field(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    drop_cap(data, TOKEN_PROTECTION)
    data["users"].append(dict(UNREGISTERED_USER))
    plan, _ = make_plan(data, manifest)
    assert plan["steps"], "mutated fixture must produce steps"
    for step in plan["steps"]:
        card = StepCard.model_validate(step)  # schema: every field mandatory
        assert card.title and card.actions and card.rollback and card.watchFor
        assert card.preconditions, card.id
        assert card.verification.query and card.verification.expected
        assert card.verification.status == "pending"
        assert card.affected.count >= 0
        for pre in card.preconditions:
            assert pre.statement and pre.query
            assert pre.result in ("pass", "fail", "unverified")


def test_every_gate_references_a_checkable_query(golden):
    data, manifest = golden
    data["users"].append(dict(UNREGISTERED_USER))
    drop_cap(data, USER_MFA)
    plan, _ = make_plan(data, manifest)
    assert plan["gates"], "the plan always carries its gates"
    for gate in plan["gates"]:
        assert gate["statement"]
        assert gate["extensionRule"]
        # Checkable: the query names the collector data or command that decides it.
        assert "iamai collect" in gate["query"] or "dataset" in gate["query"]
    gate_ids = {g["id"] for g in plan["gates"]}
    for phase in plan["phases"]:
        assert phase["gateId"] in gate_ids
    g2 = next(g for g in plan["gates"] if g["id"] == "G2")
    assert "95 percent" in g2["statement"]
    g3 = next(g for g in plan["gates"] if g["id"] == "G3")
    assert "7 consecutive days" in g3["statement"]


def test_sp_preflight_appears_on_app_targeted_cap_step(golden):
    data, manifest = golden
    drop_cap(data, TOKEN_PROTECTION)  # the app targeted policy becomes MISSING
    plan, _ = make_plan(data, manifest)
    deploy = next(s for s in steps_for(plan, TOKEN_PROTECTION) if s["phase"] == 3)
    preflight = [p for p in deploy["preconditions"] if "application" in p["statement"]]
    assert preflight, "app targeted policy must carry the service principal preflight"
    assert preflight[0]["result"] == "pass"
    assert "service_principals" in preflight[0]["query"]
    assert not any("New-MgServicePrincipal" in a for a in deploy["actions"])

    # An all-apps policy carries no preflight.
    plan_all, _ = make_plan(*_dropped(golden, USER_MFA))
    deploy_all = next(s for s in steps_for(plan_all, USER_MFA) if s["phase"] == 3)
    assert not any("application" in p["statement"] for p in deploy_all["preconditions"])


def _dropped(golden, name):
    data, manifest = copy.deepcopy(golden)
    drop_cap(data, name)
    return data, manifest


def test_sp_preflight_fails_and_adds_provisioning_when_sp_missing(golden):
    data, manifest = golden
    drop_cap(data, TOKEN_PROTECTION)
    targeted = "1c3f9714-cea8-4bb0-a077-d7023cb96b22"
    data["service_principals"] = [
        sp for sp in data["service_principals"]
        if str(sp.get("appId", "")).lower() != targeted
    ]
    plan, _ = make_plan(data, manifest)
    deploy = next(s for s in steps_for(plan, TOKEN_PROTECTION) if s["phase"] == 3)
    preflight = next(p for p in deploy["preconditions"] if "application" in p["statement"])
    assert preflight["result"] == "fail"
    # The provisioning sub-step comes before the policy creation actions.
    provisioning = [i for i, a in enumerate(deploy["actions"]) if targeted in a]
    creation = [i for i, a in enumerate(deploy["actions"]) if "New policy" in a]
    assert provisioning and creation and provisioning[0] < creation[0]
    assert any(item["item"] == targeted for item in plan["watchList"])


# --- Fixed sequencing rules ---------------------------------------------------------


def test_report_only_before_enforced(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    plan, _ = make_plan(data, manifest)
    deploy = next(s for s in steps_for(plan, USER_MFA) if s["phase"] == 3)
    enable = next(s for s in steps_for(plan, USER_MFA) if s["phase"] == 4)
    assert any("Report-only" in action for action in deploy["actions"])
    assert not any("Enable policy to On" in action for action in deploy["actions"])
    assert any("Enable policy to On" in action for action in enable["actions"])
    assert any("7 consecutive days" in p["statement"] for p in enable["preconditions"])
    assert any("95 percent" in p["statement"] for p in enable["preconditions"])
    assert deploy["controlId"] == enable["controlId"]


def test_a_policy_the_plan_deploys_is_always_enforced_later(golden):
    """A report-only policy protects nobody, so a plan that creates one must
    also enforce it. The standard accepting report-only is a grading
    concession, not a rollout target. Before this was fixed every shipped
    artifact was enabledOrReportOnly, so phase 4 was always empty while the
    checkpoint claimed enforcement had happened (BUGS.md item 1)."""
    data, manifest = golden
    drop_cap(data, USER_MFA)
    plan, _ = make_plan(data, manifest, artifact=pristine_artifact())  # enabledOrReportOnly
    phases = {s["phase"] for s in steps_for(plan, USER_MFA)}
    assert 3 in phases and 4 in phases


def test_registration_before_enforcement_with_cohort_split(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    data["users"].append(dict(UNREGISTERED_USER))
    plan, _ = make_plan(data, manifest)
    tap = next(s for s in plan["steps"] if "Temporary Access Pass" in s["title"])
    assert tap["phase"] == 2
    assert tap["affected"]["count"] == 1
    assert "user9@tenant.example" in tap["affected"]["samples"]
    enable = next(s for s in steps_for(plan, USER_MFA) if s["phase"] == 4)
    assert any("enforcement group" in action for action in enable["actions"])
    straggler = next(s for s in plan["steps"] if s["phase"] == 5 and "newly registered" in s["title"])
    assert any("past day 14" in w for w in straggler["watchFor"])
    tail = plan["phases"][-1]
    assert tail["number"] == 5 and "day 14" in tail["days"]


def test_legacy_auth_inventory_before_any_block(golden):
    data, manifest = golden
    drop_cap(data, LEGACY_BLOCK)
    plan, _ = make_plan(data, manifest)
    inventory = next(s for s in plan["steps"] if "Inventory legacy authentication" in s["title"])
    assert inventory["phase"] == 2
    enable = next(s for s in steps_for(plan, LEGACY_BLOCK) if s["phase"] == 4)
    assert any("legacy authentication inventory" in p["statement"].lower() for p in enable["preconditions"])
    assert any("30 day window" in w for w in enable["watchFor"])


def test_weakest_method_is_never_codified(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    for row in data["registration_details"]:
        row["userPreferredMethodForSecondaryAuthentication"] = "sms"
    plan, _ = make_plan(data, manifest)
    deploy = next(s for s in steps_for(plan, USER_MFA) if s["phase"] == 3)
    grant_actions = [a for a in deploy["actions"] if a.startswith("Under Grant")]
    assert any("Require multifactor authentication" in a for a in grant_actions)
    assert not any("authentication strength" in a for a in grant_actions)
    staged = [s for s in plan["steps"] if s["phase"] == 5 and "sign in strength" in s["title"]]
    assert staged, "the stronger strength requirement is its own staged step"
    assert any("text message" in w for w in staged[0]["watchFor"])

    # With a strong dominant method the strength lands immediately, unstaged.
    data2, manifest2 = load_snapshot_data(FIXTURES)
    data2, manifest2 = copy.deepcopy(data2), copy.deepcopy(manifest2)
    drop_cap(data2, USER_MFA)
    plan2, _ = make_plan(data2, manifest2)
    deploy2 = next(s for s in steps_for(plan2, USER_MFA) if s["phase"] == 3)
    assert any("Require authentication strength" in a for a in deploy2["actions"])
    assert not [s for s in plan2["steps"] if s["phase"] == 5 and "sign in strength" in s["title"]]


# --- License gating, unknowns, watch list -------------------------------------------


def test_plan_only_includes_steps_the_license_supports(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    answers = make_answers(**{"license-tier": ("singleChoice", "licenseTier", "none", ["No license"])})
    plan, _ = make_plan(data, manifest, answers=answers)
    assert not steps_for(plan, USER_MFA)
    excluded = {item["controlId"] for item in plan["notIncluded"]}
    assert excluded, "license limited protections are listed with the reason"
    for item in plan["notIncluded"]:
        assert "license" in item["reason"]

    plan_bp, _ = make_plan(*_dropped(golden, USER_MFA))
    assert steps_for(plan_bp, USER_MFA), "Business Premium supports the P1 steps"
    assert not any(i["controlId"] in {s["controlId"] for s in plan_bp["steps"]} for i in plan_bp["notIncluded"])


def test_unknown_controls_get_no_steps_and_land_in_unknowns(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    for record in manifest["datasets"]:
        if record["dataset"] == "auth_strengths":
            record["complete"] = False
    plan, assessment = make_plan(data, manifest)
    unknown_ids = {c["controlId"] for c in assessment["controls"] if c["grade"] == "UNKNOWN"}
    assert unknown_ids, "the mutation must produce UNKNOWN controls"
    step_controls = {s["controlId"] for s in plan["steps"] if s["controlId"]}
    assert not unknown_ids & step_controls
    for control_id in unknown_ids:
        assert any(control_id in u for u in plan["unknowns"])
    assert any("30 day window" in u for u in plan["unknowns"])


def test_watch_list_covers_break_glass_and_service_accounts(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    answers = make_answers(**{
        "special-handling": ("freeText", "specialHandling", "The CEO travels weekly.", []),
        "legacy-auth": ("confirmSet", "serviceAccounts", ["30000000-0000-0000-0000-000000000009"], ["scanner@tenant.example"]),
    })
    plan, _ = make_plan(data, manifest, answers=answers)
    items = {(i["kind"], i["item"]) for i in plan["watchList"]}
    assert ("account", BREAK_GLASS_LABEL) in items
    assert ("account", "scanner@tenant.example") in items
    assert any(i["reason"] == "The CEO travels weekly." for i in plan["watchList"])


# --- Comms, language, containment ---------------------------------------------------


def test_comms_templates_are_populated_and_plain(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    data["users"].append(dict(UNREGISTERED_USER))
    plan, _ = make_plan(data, manifest)
    assert set(plan["comms"]) == {"announcement", "reminder", "helpdesk"}
    for text in plan["comms"].values():
        assert text.strip()
        assert "—" not in text
        assert "day 12 of the rollout" in text or "day 11 of the rollout" in text
    assert "Temporary Access Pass" in plan["comms"]["helpdesk"]


def test_plan_language_and_html_containment(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    drop_cap(data, TOKEN_PROTECTION)
    data["users"].append(dict(UNREGISTERED_USER))
    plan, _ = make_plan(data, manifest)
    blob = json.dumps(plan, ensure_ascii=False)
    assert "—" not in blob  # no em dashes anywhere
    assert "target-tenant" == plan["tenantId"]
    html = render_plan(plan)
    assert "—" not in html
    assert "<script" not in html.lower()
    assert "https://" not in html and "http://" not in html  # self-contained
    assert "Tenant: target" in html  # alias only
    assert "Remediation plan" in html
    for step in plan["steps"]:
        assert step["title"] in html or step["title"].replace("'", "&#39;") in html
    assert "How to read this plan" in html


# --- CLI ------------------------------------------------------------------------------


runner = CliRunner()


def _combined_output(result) -> str:
    try:
        return result.output + result.stderr
    except ValueError:
        return result.output


def test_cli_plan_requires_assessment_and_answers(workspace, mock_graph):  # noqa: F811
    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    result = runner.invoke(cli.app, ["plan", "golden"])
    assert result.exit_code == 1
    assert "iamai assess" in _combined_output(result)

    assert runner.invoke(cli.app, ["assess", "golden"]).exit_code == 0
    result = runner.invoke(cli.app, ["plan", "golden"])
    assert result.exit_code == 1
    assert "questionnaire" in _combined_output(result)


def test_cli_plan_writes_plan_json_and_html(workspace, mock_graph):  # noqa: F811
    from iamai.questions import generate_questions, latest_assessment
    from iamai.store import SnapshotStore
    from test_m3_questions import _scripted_input

    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    assert runner.invoke(cli.app, ["assess", "golden"]).exit_code == 0
    store = SnapshotStore()
    assessment = latest_assessment(store, "golden")
    snapshot_dir = store.latest_snapshot("golden")
    data, _ = load_snapshot_data(snapshot_dir)
    questions = generate_questions(assessment, data, snapshot_dir)
    assert runner.invoke(cli.app, ["questions", "golden"], input=_scripted_input(questions)).exit_code == 0

    result = runner.invoke(cli.app, ["plan", "golden"])
    assert result.exit_code == 0, _combined_output(result)
    assert "Plan written to" in result.output
    assert "Phase 1 (Day 1)" in result.output

    plans_dir = store.alias_dir("golden") / "plans"
    json_files = list(plans_dir.glob("*-plan.json"))
    html_files = list(plans_dir.glob("*-plan.html"))
    assert len(json_files) == 1 and len(html_files) == 1
    plan = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert plan["alias"] == "golden"
    assert plan["steps"][0]["phase"] == 1
    for step in plan["steps"]:
        StepCard.model_validate(step)
    html = html_files[0].read_text(encoding="utf-8")
    assert "Remediation plan" in html and "<script" not in html.lower()
