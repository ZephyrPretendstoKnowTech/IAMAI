"""M3: the questionnaire engine (SPEC section 9).

Generation from the assessment (seed questions only when relevant), answer
persistence to answers.json (never asked twice), the parameter binding layer,
and the automatic regrade lifting a PARTIAL control to FULL after an
exclusion is sanctioned. Renders nothing live; everything runs from the
sanitized golden fixtures.
"""

import copy
import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

import iamai.cli as cli
from iamai.config import Config, save_config
from iamai.grade import assess_snapshot
from iamai.questions import (
    assess_with_answers,
    generate_questions,
    grade_changes,
    latest_assessment,
    load_answers,
    make_answer,
    parameters,
    pending_questions,
    save_answer,
    slot_bindings,
)
from iamai.store import SnapshotStore, load_snapshot_data

from conftest import APP_ID, TENANT_ID, make_test_client
from test_m1_canon import make_artifact

pytestmark = pytest.mark.m3

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"

USER_MFA = "Core - Allow - MFA for Internal Users"
GOLDEN_EXCLUDED_GROUP = "5137fe56-b084-441a-a61b-0dcff4e618d8"
BOGUS = "99999999-9999-9999-9999-999999999999"
KNOWN_UPN = "user2@tenant.example"
KNOWN_UPN_ID = "0cef596d-59f3-4742-a117-b335eb763903"

SIGNIN_FEEDS = ("signins_interactive.jsonl.gz", "signins_noninteractive.jsonl.gz")


@pytest.fixture()
def golden():
    data, manifest = load_snapshot_data(FIXTURES)
    return copy.deepcopy(data), copy.deepcopy(manifest)


def assess(data, manifest, artifact=None, bindings=None):
    return assess_snapshot(
        artifact or make_artifact(data), data, manifest,
        tenant_id="target-tenant", alias="target", snapshot_dir=FIXTURES,
        answer_bindings=bindings,
    )


def cap_named(data, name):
    return next(c for c in data["conditional_access_policies"] if c["displayName"] == name)


def write_snapshot(base: Path, alias: str, data: dict, manifest: dict) -> SnapshotStore:
    """Lay the fixture data out as a real snapshot under a temp data dir."""
    store = SnapshotStore(base / "data")
    raw = store.alias_dir(alias) / "20260101T000000Z" / "raw"
    raw.mkdir(parents=True)
    for name, value in data.items():
        (raw / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
    for feed in SIGNIN_FEEDS:
        shutil.copy(FIXTURES / feed, raw / feed)
    (raw.parent / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return store


# --- Generation ----------------------------------------------------------------


def test_seed_questions_generated_in_stable_order(golden):
    data, manifest = golden
    questions = generate_questions(assess(data, manifest), data, FIXTURES)
    ids = [q.id for q in questions]
    # Golden has no unsanctioned exclusions and no legacy auth events, so
    # those seed questions are correctly not generated.
    assert ids == [
        "break-glass", "trusted-locations", "license-tier",
        "report-timezone", "special-handling",
    ]
    for question in questions:
        assert question.text
        assert question.trigger
        assert question.evidence.query
        assert question.bindsTo
    by_id = {q.id: q for q in questions}
    assert by_id["break-glass"].required
    assert not by_id["special-handling"].required


def test_break_glass_candidates_from_exclusions_and_signin_absence(golden):
    data, manifest = golden
    data["users"].append({
        "id": "40000000-0000-0000-0000-000000000004",
        "userPrincipalName": "user9@tenant.example",
        "accountEnabled": True,
        "userType": "Member",
    })
    question = generate_questions(assess(data, manifest), data, FIXTURES)[0]
    values = [option.value for option in question.options]
    assert GOLDEN_EXCLUDED_GROUP in values
    assert "40000000-0000-0000-0000-000000000004" in values
    details = [row["detail"] for row in question.evidence.rows]
    assert any("Excluded from the policy" in d for d in details)
    assert any("No sign in activity" in d for d in details)


def test_trusted_locations_question_shows_egress_ips(golden):
    data, manifest = golden
    questions = generate_questions(assess(data, manifest), data, FIXTURES)
    question = next(q for q in questions if q.id == "trusted-locations")
    assert question.options, "sign in egress addresses should be offered"
    assert any("sign in" in row["detail"] for row in question.evidence.rows)
    # Each address shows its share of the window, and an address carrying a
    # large share is flagged as a likely office or VPN, a hint for the operator.
    assert any("% of the window" in row["detail"] for row in question.evidence.rows)
    assert any(
        "office network or VPN" in row["detail"] for row in question.evidence.rows
    ), "a dominant egress address should be flagged as a likely office/VPN"


def test_exclusion_question_generated_for_unsanctioned_exclusion(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    cap_named(data, USER_MFA)["conditions"]["users"]["excludeUsers"] = [BOGUS]
    assessment = assess(data, manifest, artifact)
    questions = generate_questions(assessment, data, FIXTURES)
    question = next(q for q in questions if q.id == f"exclusion-{BOGUS}")
    assert question.subject == BOGUS
    assert question.answerType == "singleChoice"
    assert {o.value for o in question.options} == {
        "breakGlassAccounts", "serviceAccounts", "pilotGroups", "onboardingGroups", "other",
    }
    items = [row["item"] for row in question.evidence.rows]
    assert USER_MFA in items


def test_questions_never_asked_twice(golden, tmp_path):
    data, manifest = golden
    questions = generate_questions(assess(data, manifest), data, FIXTURES)
    answers = load_answers(tmp_path, "target-tenant", "target")
    answer = make_answer(questions[0], [], data)
    save_answer(tmp_path, answers, answer)
    reloaded = load_answers(tmp_path, "target-tenant", "target")
    pending = pending_questions(questions, reloaded)
    assert "break-glass" not in [q.id for q in pending]
    assert len(pending) == len(questions) - 1


# --- Persistence and binding ------------------------------------------------------


def test_answers_persist_and_upns_resolve_to_object_ids(golden, tmp_path):
    data, manifest = golden
    question = generate_questions(assess(data, manifest), data, FIXTURES)[0]
    answers = load_answers(tmp_path, "target-tenant", "target")
    # An entry that names nothing in the tenant is rejected rather than stored
    # and then silently dropped by slot_bindings. Every account the question
    # can be about is in the snapshot, so an unresolvable one is a typo, and
    # accepting it produced an answer that looked recorded and did nothing
    # (BUGS.md item 28).
    with pytest.raises(ValueError, match="not accounts or groups in this tenant"):
        make_answer(question, [KNOWN_UPN, "unknown@nowhere.example"], data)

    answer = make_answer(question, [KNOWN_UPN], data)
    path = save_answer(tmp_path, answers, answer)
    assert path == tmp_path / "answers.json"

    reloaded = load_answers(tmp_path, "target-tenant", "target")
    assert KNOWN_UPN_ID in reloaded.answers["break-glass"].value
    assert slot_bindings(reloaded) == {"breakGlassAccounts": [KNOWN_UPN_ID]}


def test_exclusion_classification_binds_the_chosen_slot(golden, tmp_path):
    data, manifest = golden
    artifact = make_artifact(data)
    cap_named(data, USER_MFA)["conditions"]["users"]["excludeUsers"] = [BOGUS]
    assessment = assess(data, manifest, artifact)
    question = next(
        q for q in generate_questions(assessment, data, FIXTURES)
        if q.id == f"exclusion-{BOGUS}"
    )
    answers = load_answers(tmp_path, "target-tenant", "target")
    save_answer(tmp_path, answers, make_answer(question, "serviceAccounts", data))
    assert slot_bindings(answers) == {"serviceAccounts": [BOGUS]}


def test_other_classification_needs_a_reason_and_binds_nothing(golden, tmp_path):
    data, manifest = golden
    artifact = make_artifact(data)
    cap_named(data, USER_MFA)["conditions"]["users"]["excludeUsers"] = [BOGUS]
    assessment = assess(data, manifest, artifact)
    question = next(
        q for q in generate_questions(assessment, data, FIXTURES)
        if q.id == f"exclusion-{BOGUS}"
    )
    with pytest.raises(ValueError):
        make_answer(question, "other", data)
    answers = load_answers(tmp_path, "target-tenant", "target")
    save_answer(tmp_path, answers, make_answer(question, "other", data, note="A contractor account"))
    assert slot_bindings(answers) == {}
    assert answers.answers[question.id].note == "A contractor account"


def test_timezone_dropdown_validates_and_optional_free_text_allows_empty(golden):
    data, manifest = golden
    questions = generate_questions(assess(data, manifest), data, FIXTURES)
    by_id = {q.id: q for q in questions}
    # The timezone is now a selectOne dropdown of IANA zones. A name outside the
    # set is rejected at answer time, instead of being accepted and then
    # silently falling back to UTC in the plan.
    tz = by_id["report-timezone"]
    assert tz.answerType == "selectOne"
    assert any(option.value == "Australia/Sydney" for option in tz.options)
    with pytest.raises(ValueError):
        make_answer(tz, "Nowhere/Nonsense", data)
    assert make_answer(tz, "UTC", data).value == "UTC"
    # Optional free text still accepts an empty answer.
    assert make_answer(by_id["special-handling"], "", data).value == ""


def test_parameters_view_for_the_plan(golden, tmp_path):
    data, manifest = golden
    questions = generate_questions(assess(data, manifest), data, FIXTURES)
    by_id = {q.id: q for q in questions}
    answers = load_answers(tmp_path, "target-tenant", "target")
    save_answer(tmp_path, answers, make_answer(by_id["break-glass"], [KNOWN_UPN], data))
    ip_option = by_id["trusted-locations"].options[0].value
    save_answer(tmp_path, answers, make_answer(by_id["trusted-locations"], [ip_option], data))
    save_answer(tmp_path, answers, make_answer(by_id["license-tier"], "P1", data))
    save_answer(tmp_path, answers, make_answer(by_id["report-timezone"], "UTC", data))
    params = parameters(answers)
    assert params["slots"] == {"breakGlassAccounts": [KNOWN_UPN_ID]}
    assert params["licenseTier"] == "P1"
    assert params["reportTimezone"] == "UTC"
    assert params["trustedNetworks"] == [ip_option]


def test_language_rules_in_generated_questions(golden):
    data, manifest = golden
    artifact = make_artifact(data)
    cap_named(data, USER_MFA)["conditions"]["users"]["excludeUsers"] = [BOGUS]
    assessment = assess(data, manifest, artifact)
    for question in generate_questions(assessment, data, FIXTURES):
        blob = json.dumps(question.model_dump(), ensure_ascii=False)
        assert "—" not in blob, question.id  # no em dashes anywhere


# --- Regrade: the M3 acceptance core -----------------------------------------------


def test_sanctioned_exclusion_regrades_partial_to_full(golden, tmp_path):
    data, manifest = golden
    artifact = make_artifact(data)
    control_id = next(
        c["id"] for c in artifact["controls"] if c.get("sourceName") == USER_MFA
    )
    cap_named(data, USER_MFA)["conditions"]["users"]["excludeUsers"] = [BOGUS]
    store = write_snapshot(tmp_path, "target", data, manifest)

    first, first_path, first_report, count = assess_with_answers(
        "target", "target-tenant", artifact, store
    )
    assert count == 0
    graded = {c["controlId"]: c for c in first["controls"]}
    assert graded[control_id]["grade"] == "PARTIAL"
    assert graded[control_id]["unsanctionedExclusions"] == [f"user:{BOGUS}"]
    assert first_path.exists() and first_report.exists()
    assert latest_assessment(store, "target")["generatedAt"] == first["generatedAt"]

    question = next(
        q for q in generate_questions(first, data, first_path.parent.parent / "20260101T000000Z")
        if q.id == f"exclusion-{BOGUS}"
    )
    answers = load_answers(store.alias_dir("target"), "target-tenant", "target")
    save_answer(store.alias_dir("target"), answers, make_answer(question, "breakGlassAccounts", data))

    second, second_path, second_report, count = assess_with_answers(
        "target", "target-tenant", artifact, store
    )
    assert count == 1
    regraded = {c["controlId"]: c for c in second["controls"]}
    assert regraded[control_id]["grade"] == "FULL"
    assert second["gradeCounts"].get("PARTIAL", 0) == 0
    assert second_path != first_path and second_path.exists() and second_report.exists()
    assert grade_changes(first, second) == [
        {"controlId": control_id, "from": "PARTIAL", "to": "FULL"}
    ]


# --- CLI runner ---------------------------------------------------------------------


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


def _scripted_input(questions) -> str:
    """One deterministic input line set per pending question, by answer type."""
    lines: list[str] = []
    for question in questions:
        if question.answerType in ("freeText", "selectOne"):
            lines.append("UTC")
        elif question.answerType == "singleChoice":
            lines.append("1")
        elif question.answerType == "confirmSet":
            lines.extend(["n"] * len(question.options))
        else:
            lines.append("none")
    return "\n".join(lines) + "\n"


def test_cli_runner_completes_the_flow_and_regrades(workspace, mock_graph):
    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    assert runner.invoke(cli.app, ["assess", "golden"]).exit_code == 0

    store = SnapshotStore()
    assessment = latest_assessment(store, "golden")
    snapshot_dir = store.latest_snapshot("golden")
    data, _ = load_snapshot_data(snapshot_dir)
    questions = generate_questions(assessment, data, snapshot_dir)

    result = runner.invoke(cli.app, ["questions", "golden"], input=_scripted_input(questions))
    assert result.exit_code == 0, result.output
    assert "Question 1 of" in result.output
    assert "Why we ask:" in result.output
    assert "Answers saved. The assessment was regraded with them." in result.output
    assert "Report written to" in result.output

    answers = load_answers(store.alias_dir("golden"), TENANT_ID, "golden")
    assert set(answers.answers) == {q.id for q in questions}

    again = runner.invoke(cli.app, ["questions", "golden"], input="")
    assert again.exit_code == 0, again.output
    assert "Every question is already answered." in again.output

    reassess = runner.invoke(cli.app, ["assess", "golden"])
    assert reassess.exit_code == 0, reassess.output
    assert "Applied" in reassess.output and "saved questionnaire" in reassess.output


def test_cli_runner_requires_an_assessment_first(workspace, mock_graph):
    assert runner.invoke(cli.app, ["baseline", "build", "--yes"]).exit_code == 0
    result = runner.invoke(cli.app, ["questions", "target"])
    assert result.exit_code == 1
    try:
        combined = result.output + result.stderr
    except ValueError:  # older click merges stderr into output already
        combined = result.output
    assert "Run 'iamai assess target' first" in combined
