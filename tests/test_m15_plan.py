"""Stage 5 of the first-run work order: the plan reconciles three inputs.

Grades come from code and evidence and are immutable downstream: no
questionnaire answer, conversational context, or accepted deviation may
change one. All of those may change the plan, and every step says what drove
it, so a reader can tell the generic parts from the tenant-specific ones.
"""

import copy
import json
from pathlib import Path

import pytest

from iamai.grade import assess_snapshot
from iamai.plan import generate_plan, load_conversation, load_deviations
from iamai.store import load_snapshot_data

from test_m4_plan import FIXTURES, drop_cap, enforced_artifact, make_answers

pytestmark = pytest.mark.m15

USER_MFA = "Core - Allow - MFA for Internal Users"


@pytest.fixture
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return copy.deepcopy(data), manifest


def _assess(data, manifest, artifact):
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
    )


def _plan(assessment, artifact, data, **kwargs):
    return generate_plan(
        assessment, make_answers(), artifact, data,
        tenant_id="target-tenant", alias="target", **kwargs,
    )


def _first_gap_control(assessment):
    return next(c for c in assessment["controls"] if c["grade"] in ("PARTIAL", "MISSING"))


# --- Grades are immutable across every plan input ------------------------------


def test_no_plan_input_can_change_a_grade(golden, tmp_path):
    """The boundary of the whole design: an accepted deviation and a
    conversational constraint reach plan generation and only plan
    generation. Grading has no code path that reads either file, so two
    assessments straddling their creation are grade-identical."""
    data, manifest = golden
    drop_cap(data, USER_MFA)
    artifact = enforced_artifact()

    before = _assess(data, manifest, artifact)
    alias_dir = tmp_path / "data" / "target"
    alias_dir.mkdir(parents=True)
    (alias_dir / "deviations.json").write_text(json.dumps({
        "schemaVersion": 1,
        "deviations": [{"controlId": _first_gap_control(before)["controlId"],
                        "reason": "Accepted for the test", "reviewBy": "2099-01-01"}],
    }), encoding="utf-8")
    (alias_dir / "conversation.json").write_text(json.dumps({
        "schemaVersion": 1,
        "statements": [{"text": "Defer everything forever",
                        "controlIds": [c["controlId"] for c in before["controls"]],
                        "deferUntil": "2099-01-01"}],
    }), encoding="utf-8")
    after = _assess(data, manifest, artifact)

    strip = lambda a: [{k: v for k, v in c.items() if k != "tenantId"} for c in a["controls"]]
    assert strip(before) == strip(after)
    assert before["gradeCounts"] == after["gradeCounts"]


# --- Provenance per step --------------------------------------------------------


def test_every_step_declares_what_drove_it(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    artifact = enforced_artifact()
    plan = _plan(_assess(data, manifest, artifact), artifact, data)
    for step in plan["steps"]:
        sources = [p["source"] for p in step["drivenBy"]]
        assert sources, step["title"]
        assert sources[0] == "standard"


def test_answer_driven_steps_name_the_questionnaire(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    artifact = enforced_artifact()
    plan = _plan(_assess(data, manifest, artifact), artifact, data)
    break_glass = plan["steps"][0]
    assert "break glass" in break_glass["title"].lower()
    assert any(p["source"] == "questionnaire" for p in break_glass["drivenBy"])


# --- Accepted deviations --------------------------------------------------------


def test_an_accepted_deviation_replaces_the_step_with_the_record(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    artifact = enforced_artifact()
    assessment = _assess(data, manifest, artifact)
    gap = _first_gap_control(assessment)

    without = _plan(assessment, artifact, data)
    with_dev = _plan(assessment, artifact, data, deviations=[{
        "controlId": gap["controlId"],
        "reason": "Warehouse staff on shared kiosks cannot use this method.",
        "decidedBy": "J. Reyes",
        "decidedAt": "2026-08-17",
        "compensatingControl": "Kiosk accounts sign in only from the warehouse network.",
        "reviewBy": "2099-02-01",
    }])

    assert any(s["controlId"] == gap["controlId"] for s in without["steps"])
    assert not any(s["controlId"] == gap["controlId"] for s in with_dev["steps"])
    record = with_dev["acceptedDeviations"][0]
    assert record["status"] == "accepted"
    assert record["decidedBy"] == "J. Reyes"
    assert record["reviewBy"] == "2099-02-01"
    # The grade itself is untouched; the record does not touch the assessment.
    assert gap["grade"] in ("PARTIAL", "MISSING")


def test_a_lapsed_deviation_returns_the_step_and_says_why(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    artifact = enforced_artifact()
    assessment = _assess(data, manifest, artifact)
    gap = _first_gap_control(assessment)

    plan = _plan(assessment, artifact, data, deviations=[{
        "controlId": gap["controlId"], "reason": "old decision", "reviewBy": "2020-01-01",
    }])
    assert any(s["controlId"] == gap["controlId"] for s in plan["steps"])
    assert plan["acceptedDeviations"][0]["status"] == "review due"
    assert any("due for review" in c for c in plan["conflicts"])


def test_a_deviation_the_tenant_now_meets_is_flagged_not_deleted(golden):
    data, manifest = golden
    artifact = enforced_artifact()
    assessment = _assess(data, manifest, artifact)
    met = next(c for c in assessment["controls"] if c["grade"] in ("FULL", "FUNCTIONAL"))

    plan = _plan(assessment, artifact, data, deviations=[{
        "controlId": met["controlId"], "reason": "was accepted once", "reviewBy": "2099-01-01",
    }])
    assert plan["acceptedDeviations"][0]["status"] == "no longer needed"
    assert any("no longer shows a gap" in c for c in plan["conflicts"])


# --- Conversation context -------------------------------------------------------


def test_a_constraint_re_sequences_the_step_and_says_who_said_so(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    artifact = enforced_artifact()
    assessment = _assess(data, manifest, artifact)
    gap = _first_gap_control(assessment)

    plan = _plan(assessment, artifact, data, conversation=[{
        "text": "The finance app still uses legacy auth until the March migration.",
        "recordedAt": "2026-08-17",
        "controlIds": [gap["controlId"]],
        "deferUntil": "2027-03-31",
    }])
    step = next(s for s in plan["steps"] if s["controlId"] == gap["controlId"])
    assert step["phase"] == 5
    assert any(p["source"] == "conversation" and "March migration" in p["detail"]
               for p in step["drivenBy"])
    assert any("Not before 2027-03-31" in p["statement"] for p in step["preconditions"])


def test_a_day_one_step_is_never_deferred(golden):
    data, manifest = golden
    drop_cap(data, USER_MFA)
    artifact = enforced_artifact()
    assessment = _assess(data, manifest, artifact)

    plan = _plan(assessment, artifact, data, conversation=[{
        "text": "Can we do the emergency accounts next quarter?",
        "controlIds": [""],  # the break-glass step has no controlId
        "deferUntil": "2027-01-01",
    }])
    first = plan["steps"][0]
    assert first["phase"] == 1
    assert any("day one safety step" in c for c in plan["conflicts"])


# --- The input files ------------------------------------------------------------


def test_the_loaders_tolerate_absence_and_garbage(tmp_path):
    assert load_deviations(tmp_path) == []
    assert load_conversation(tmp_path) == []
    (tmp_path / "deviations.json").write_text("not json", encoding="utf-8")
    (tmp_path / "conversation.json").write_text("[]", encoding="utf-8")
    assert load_deviations(tmp_path) == []
    assert load_conversation(tmp_path) == []


def test_the_plan_validates_against_its_schema_with_the_new_fields(golden):
    from test_artifact_schema import validate

    data, manifest = golden
    drop_cap(data, USER_MFA)
    artifact = enforced_artifact()
    assessment = _assess(data, manifest, artifact)
    gap = _first_gap_control(assessment)
    plan = _plan(assessment, artifact, data,
                 deviations=[{"controlId": gap["controlId"], "reason": "r", "reviewBy": "2099-01-01"}],
                 conversation=[{"text": "context", "controlIds": [gap["controlId"]]}])
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "plan.schema.json")
                        .read_text(encoding="utf-8"))
    validate(plan, schema, defs=schema.get("$defs"))
