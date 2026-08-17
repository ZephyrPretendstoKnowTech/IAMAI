"""PUB-M2b: cross-tenant MFA trust and the device code carve out.

Authored against the sources recorded in ASSUMPTIONS.md note 37. The trust
control encodes an operator-facing risk decision rather than a required
setting (SPEC-PUBLIC section 7 item 9), and the carve out control encodes
the shape judgement deferred from PUB-M2 (section 7 item 10): an exception
for meeting room hardware belongs on accounts or a group, never on an
application.
"""

import copy
import json
from pathlib import Path

import httpx
import pytest

from iamai.collectors import CollectContext, cross_tenant
from iamai.grade import (
    FULL,
    PARTIAL,
    UNKNOWN,
    _cross_tenant_summary,
    _device_code_carveout_summary,
    assess_snapshot,
)
from iamai.store import SnapshotStore, load_snapshot_data

from conftest import GRAPH, make_test_client

pytestmark = pytest.mark.m12

FIXTURES = Path(__file__).parent / "fixtures" / "golden_sanitized"
PACK = json.loads(
    (Path(__file__).parents[1] / "src" / "iamai" / "packs" / "basics-v1.json").read_text(encoding="utf-8")
)

PARTNER = "44444444-4444-4444-4444-444444444444"


def control(control_id):
    return next(c for c in PACK["controls"] if c["id"] == control_id)


def no_trust_default():
    return {"isServiceDefault": True, "inboundTrust": {"isMfaAccepted": False}}


def trusting_default():
    return {"isServiceDefault": False, "inboundTrust": {"isMfaAccepted": True}}


def trusting_partner(tenant_id=PARTNER):
    return {"tenantId": tenant_id, "inboundTrust": {"isMfaAccepted": True}}


def inheriting_partner(tenant_id=PARTNER):
    # A partner configuration's null fields inherit the default, so a null
    # inboundTrust proves nothing on its own (ASSUMPTIONS.md note 37).
    return {"tenantId": tenant_id, "inboundTrust": None}


# --- Collector ----------------------------------------------------------------


@pytest.fixture
def context(tmp_path):
    writer = SnapshotStore(tmp_path / "data").new_snapshot("golden")
    return CollectContext(writer=writer)


def test_collector_reads_default_and_partners(graph_mock, context):
    graph_mock.get(f"{GRAPH}/v1.0/policies/crossTenantAccessPolicy/default").respond(
        json=no_trust_default()
    )
    graph_mock.get(f"{GRAPH}/v1.0/policies/crossTenantAccessPolicy/partners").respond(
        json={"value": [trusting_partner()]}
    )
    outcome = cross_tenant.collect(make_test_client(), context)
    assert outcome.complete
    assert outcome.count == 2
    assert outcome.data["default"]["isServiceDefault"] is True
    assert outcome.data["partners"][0]["tenantId"] == PARTNER


def test_collector_keeps_partners_when_the_default_is_unreadable(graph_mock, context):
    """Half a read is still evidence: a partner that explicitly trusts proves
    trust regardless of what the unreadable default would have said."""
    graph_mock.get(f"{GRAPH}/v1.0/policies/crossTenantAccessPolicy/default").respond(
        status_code=403, json={"error": {"code": "Authorization_RequestDenied"}}
    )
    graph_mock.get(f"{GRAPH}/v1.0/policies/crossTenantAccessPolicy/partners").respond(
        json={"value": [trusting_partner()]}
    )
    outcome = cross_tenant.collect(make_test_client(), context)
    assert not outcome.complete
    assert outcome.data["default"] is None
    assert outcome.data["partners"][0]["tenantId"] == PARTNER
    assert outcome.errors


def test_collector_reports_nothing_readable_as_absent_data(graph_mock, context):
    for path in ("default", "partners"):
        graph_mock.get(f"{GRAPH}/v1.0/policies/crossTenantAccessPolicy/{path}").respond(
            status_code=403, json={"error": {"code": "Authorization_RequestDenied"}}
        )
    outcome = cross_tenant.collect(make_test_client(), context)
    assert outcome.data is None
    assert not outcome.complete


# --- The trust summary --------------------------------------------------------


def test_trust_via_the_default_applies_to_everyone():
    summary = _cross_tenant_summary(
        {"cross_tenant_access": {"default": trusting_default(), "partners": []}}, {}
    )
    assert summary["mfaTrustAccepted"] is True
    assert summary["trustScope"] == "everyone"


def test_trust_via_one_partner_applies_even_when_the_default_says_no():
    summary = _cross_tenant_summary(
        {"cross_tenant_access": {"default": no_trust_default(),
                                 "partners": [trusting_partner()]}}, {}
    )
    assert summary["mfaTrustAccepted"] is True
    assert summary["trustScope"] == "partners"
    assert summary["trustingPartnerTenantIds"] == [PARTNER]


def test_an_inheriting_partner_does_not_count_as_explicit_trust():
    summary = _cross_tenant_summary(
        {"cross_tenant_access": {"default": no_trust_default(),
                                 "partners": [inheriting_partner()]}}, {}
    )
    assert summary["mfaTrustAccepted"] is False


def test_a_missing_dataset_has_no_answer():
    assert _cross_tenant_summary({}, {}) is None


def test_an_unreadable_default_with_no_trusting_partner_has_no_answer():
    """The default could say either thing, so neither is claimed."""
    assert _cross_tenant_summary(
        {"cross_tenant_access": {"default": None, "partners": [inheriting_partner()]}}, {}
    ) is None


def test_an_unreadable_default_with_a_trusting_partner_still_answers():
    summary = _cross_tenant_summary(
        {"cross_tenant_access": {"default": None, "partners": [trusting_partner()]}}, {}
    )
    assert summary["mfaTrustAccepted"] is True


# --- Grading the trust control ------------------------------------------------


def assess_trust(collected, answer_bindings=None):
    data, manifest = load_snapshot_data(FIXTURES)
    data = copy.deepcopy(data)
    data["cross_tenant_access"] = collected
    artifact = {"schemaVersion": 2,
                "controls": [copy.deepcopy(control("xtenant-001"))], "parameters": []}
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
        answer_bindings=answer_bindings,
    )


def test_no_trust_means_nothing_to_confirm():
    result = assess_trust({"default": no_trust_default(), "partners": []})
    assert result["controls"] == []
    assert result["notApplicable"][0]["controlId"] == "xtenant-001"


def test_unconfirmed_trust_grades_down():
    result = assess_trust({"default": trusting_default(), "partners": []})
    assert result["controls"][0]["grade"] == PARTIAL


def test_a_recorded_deliberate_decision_lifts_the_grade():
    result = assess_trust(
        {"default": trusting_default(), "partners": []},
        answer_bindings={"decision:crossTenantMfaTrust": ["deliberate"]},
    )
    assert result["controls"][0]["grade"] == FULL


def test_an_answer_that_asks_for_review_does_not_lift_the_grade():
    result = assess_trust(
        {"default": trusting_default(), "partners": []},
        answer_bindings={"decision:crossTenantMfaTrust": ["review"]},
    )
    assert result["controls"][0]["grade"] == PARTIAL


def test_an_uncollected_dataset_grades_unknown():
    data, manifest = load_snapshot_data(FIXTURES)
    artifact = {"schemaVersion": 2,
                "controls": [copy.deepcopy(control("xtenant-001"))], "parameters": []}
    result = assess_snapshot(
        artifact, dict(data), manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
    )
    assert result["controls"][0]["grade"] == UNKNOWN


# --- The device code carve out ------------------------------------------------


def block_policy(**overrides):
    policy = {
        "id": "50000000-0000-0000-0000-000000000001",
        "displayName": "Block device code",
        "state": "enabled",
        "grantControls": {"builtInControls": ["block"]},
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "authenticationFlows": {"transferMethods": "deviceCodeFlow"},
        },
    }
    conditions = overrides.pop("conditions", None)
    policy.update(overrides)
    if conditions:
        policy["conditions"] = {**policy["conditions"], **conditions}
    return policy


def test_a_clean_block_has_no_carve_out_to_judge():
    summary = _device_code_carveout_summary([block_policy()], {})
    assert summary["blocksDeviceCode"] is True
    assert summary["hasCarveOut"] is False


def test_a_group_scoped_carve_out_is_the_right_shape():
    policy = block_policy(conditions={
        "users": {"includeUsers": ["All"], "excludeGroups": ["30000000-0000-0000-0000-000000000009"]},
    })
    summary = _device_code_carveout_summary([policy], {})
    assert summary["hasCarveOut"] is True
    assert summary["applicationCarveOutCount"] == 0
    assert summary["userOrGroupCarveOutCount"] == 1


def test_an_excluded_application_is_the_wrong_shape():
    policy = block_policy(conditions={
        "applications": {"includeApplications": ["All"],
                         "excludeApplications": ["00000003-0000-0ff1-ce00-000000000000"]},
    })
    summary = _device_code_carveout_summary([policy], {})
    assert summary["applicationCarveOutCount"] == 1


def test_a_block_that_reaches_less_than_every_application_is_the_wrong_shape():
    policy = block_policy(conditions={
        "applications": {"includeApplications": ["00000003-0000-0ff1-ce00-000000000000"]},
    })
    summary = _device_code_carveout_summary([policy], {})
    assert summary["applicationCarveOutCount"] == 1


def test_a_disabled_block_does_not_count():
    summary = _device_code_carveout_summary([block_policy(state="disabled")], {})
    assert summary["blocksDeviceCode"] is False


def test_a_skipped_policy_pull_has_no_answer():
    status = {"conditional_access_policies": {"dataset": "conditional_access_policies",
                                              "skipped": True, "complete": False}}
    assert _device_code_carveout_summary([], status) is None


def assess_carveout(caps):
    data, manifest = load_snapshot_data(FIXTURES)
    data = copy.deepcopy(data)
    data["conditional_access_policies"] = caps
    artifact = {"schemaVersion": 2,
                "controls": [copy.deepcopy(control("devicecode-001"))], "parameters": []}
    return assess_snapshot(
        artifact, data, manifest,
        tenant_id="t", alias="target", snapshot_dir=FIXTURES,
    )


def test_no_carve_out_means_the_control_does_not_apply():
    result = assess_carveout([block_policy()])
    assert result["controls"] == []
    assert result["notApplicable"][0]["controlId"] == "devicecode-001"


def test_an_account_scoped_carve_out_passes():
    policy = block_policy(conditions={
        "users": {"includeUsers": ["All"], "excludeGroups": ["30000000-0000-0000-0000-000000000009"]},
    })
    assert assess_carveout([policy])["controls"][0]["grade"] == FULL


def test_an_application_scoped_carve_out_fails():
    policy = block_policy(conditions={
        "applications": {"includeApplications": ["All"],
                         "excludeApplications": ["00000003-0000-0ff1-ce00-000000000000"]},
    })
    result = assess_carveout([policy])
    assert result["controls"][0]["grade"] == PARTIAL
    assert "every person" in result["controls"][0]["coverageGaps"][0]


# --- The question and its binding ---------------------------------------------

from iamai.questions import (
    AnswersFile,
    _cross_tenant_trust_question,
    make_answer,
    slot_bindings,
)


def test_the_question_only_appears_when_trust_is_accepted():
    assert _cross_tenant_trust_question(
        {"cross_tenant_access": {"default": no_trust_default(), "partners": []}}
    ) is None
    question = _cross_tenant_trust_question(
        {"cross_tenant_access": {"default": no_trust_default(),
                                 "partners": [trusting_partner()]}}
    )
    assert question is not None
    assert PARTNER in json.dumps(question.evidence.model_dump())


def test_the_answer_reaches_the_engine_as_a_decision_binding():
    question = _cross_tenant_trust_question(
        {"cross_tenant_access": {"default": trusting_default(), "partners": []}}
    )
    answer = make_answer(question, "deliberate", {})
    answers = AnswersFile(tenantId="t", alias="a", answers={question.id: answer})
    bindings = slot_bindings(answers)
    assert bindings["decision:crossTenantMfaTrust"] == ["deliberate"]


def test_a_decision_value_never_lands_in_a_parameter_slot():
    question = _cross_tenant_trust_question(
        {"cross_tenant_access": {"default": trusting_default(), "partners": []}}
    )
    answer = make_answer(question, "review", {})
    answers = AnswersFile(tenantId="t", alias="a", answers={question.id: answer})
    for slot, values in slot_bindings(answers).items():
        if not slot.startswith("decision:"):
            assert "review" not in values


# --- The plan has somewhere for both findings to go ---------------------------

from iamai.plan import _cross_tenant_step, _device_code_carveout_step


def test_both_new_findings_produce_a_complete_step():
    trust_result = {"controlId": "xtenant-001", "riskClass": "medium"}
    carve_result = {"controlId": "devicecode-001", "riskClass": "medium"}
    empty = AnswersFile(tenantId="t", alias="a")
    for step in (_cross_tenant_step(trust_result, empty),
                 _device_code_carveout_step(carve_result)):
        assert step.title and step.actions and step.rollback and step.watchFor
        assert step.verification.query and step.verification.expected
        for action in step.actions:
            assert len(action) <= 300


def test_the_trust_step_changes_once_the_answer_asked_for_review():
    question = _cross_tenant_trust_question(
        {"cross_tenant_access": {"default": trusting_default(), "partners": []}}
    )
    answer = make_answer(question, "review", {})
    answers = AnswersFile(tenantId="t", alias="a", answers={question.id: answer})
    unanswered = _cross_tenant_step({"controlId": "xtenant-001"}, AnswersFile(tenantId="t", alias="a"))
    answered = _cross_tenant_step({"controlId": "xtenant-001"}, answers)
    assert unanswered.actions != answered.actions
    assert any("wizard" in a for a in unanswered.actions)


# --- Shipped packs carry no placeholder citations ------------------------------

from iamai.canon import validate_pack


def test_no_shipped_pack_carries_a_placeholder_citation():
    """A citation is a claim the control covers that published item, and the
    crosswalk repeats the claim to the reader, so a placeholder that reaches a
    public artifact is a credibility claim with nothing behind it
    (SPEC-PUBLIC section 11)."""
    packs_dir = Path(__file__).parents[1] / "src" / "iamai" / "packs"
    for path in packs_dir.glob("*.json"):
        blob = path.read_text(encoding="utf-8")
        assert "PLACEHOLDER" not in blob, path.name
        assert validate_pack(json.loads(blob)) == [], path.name


def test_validate_pack_rejects_a_placeholder_citation():
    pack = copy.deepcopy(PACK)
    pack["controls"][0]["citations"] = [{"source": "PLACEHOLDER", "item": "x"}]
    errors = validate_pack(pack)
    assert any("placeholder" in e.lower() for e in errors)


def test_the_crosswalk_skips_placeholder_citations_in_old_artifacts():
    from iamai.report import _compliance_crosswalk

    crosswalk = _compliance_crosswalk([
        {"grade": FULL, "citations": [{"source": "PLACEHOLDER", "item": "x"},
                                      {"source": "Real source", "item": "R.1"}]},
    ])
    assert [group["source"] for group in crosswalk] == ["Real source"]


# --- The sanitizer covers the new dataset --------------------------------------

import tempfile

from iamai.sanitize import Pseudonymizer, sanitize_node


def test_partner_tenant_ids_are_pseudonymized():
    """A partner tenantId identifies another real organisation, so it must
    leave a sanitized snapshot the same way this tenant's own ids do."""
    pseudo = Pseudonymizer(Path(tempfile.mkdtemp()) / "pseudo_map.json")
    node = {"default": no_trust_default(),
            "partners": [trusting_partner("deadbeef-dead-beef-dead-beefdeadbeef")]}
    out = sanitize_node(pseudo, node)
    blob = json.dumps(out)
    assert "deadbeef-dead-beef-dead-beefdeadbeef" not in blob
    # The structural strings are configuration vocabulary, not identity.
    assert out["partners"][0]["inboundTrust"]["isMfaAccepted"] is True
