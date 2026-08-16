"""Per-collector tests against recorded fixture responses."""

import gzip
import json
from urllib.parse import unquote_plus

import pytest

from iamai.collectors import (
    CollectContext,
    auth_methods_policy,
    auth_strengths,
    authorization_policy,
    cap_policies,
    domains,
    groups,
    named_locations,
    org_licenses,
    registration_details,
    risky_users,
    roles,
    run_all,
    security_defaults,
    service_principals,
    signins,
    users,
)
from iamai.store import SnapshotStore

from conftest import GRAPH, GROUP_EXCLUDED

pytestmark = pytest.mark.m0


@pytest.fixture
def context(tmp_path):
    writer = SnapshotStore(tmp_path / "data").new_snapshot("golden")
    return CollectContext(writer=writer)


def test_cap_policies(graph_client, mock_graph, context):
    outcome = cap_policies.collect(graph_client, context)
    assert outcome.count == 2
    assert outcome.data[0]["state"] == "enabled"
    assert outcome.api_version == "v1.0"


def test_named_locations(graph_client, mock_graph, context):
    outcome = named_locations.collect(graph_client, context)
    assert outcome.count == 2
    types = {item["@odata.type"] for item in outcome.data}
    assert types == {
        "#microsoft.graph.ipNamedLocation",
        "#microsoft.graph.countryNamedLocation",
    }


def test_auth_strengths(graph_client, mock_graph, context):
    outcome = auth_strengths.collect(graph_client, context)
    assert outcome.count == 1
    assert "allowedCombinations" in outcome.data[0]


def test_auth_methods_policy(graph_client, mock_graph, context):
    outcome = auth_methods_policy.collect(graph_client, context)
    assert outcome.count == 1
    campaign = outcome.data["registrationEnforcement"][
        "authenticationMethodsRegistrationCampaign"
    ]
    assert campaign["state"] == "enabled"
    assert outcome.data["authenticationMethodConfigurations"]


def test_security_defaults(graph_client, mock_graph, context):
    outcome = security_defaults.collect(graph_client, context)
    assert outcome.data["isEnabled"] is False


def test_authorization_policy(graph_client, mock_graph, context):
    outcome = authorization_policy.collect(graph_client, context)
    assert "defaultUserRolePermissions" in outcome.data


def test_users_pages_fully(graph_client, mock_graph, context):
    outcome = users.collect(graph_client, context)
    assert outcome.count == 3  # two pages followed via nextLink
    first_request = mock_graph["users"].calls[0].request
    assert "signInActivity" in str(first_request.url)
    assert "%24top=500" in str(first_request.url) or "$top=500" in str(first_request.url)


def test_registration_details(graph_client, mock_graph, context):
    outcome = registration_details.collect(graph_client, context)
    assert outcome.count == 2
    assert outcome.data[0]["isMfaCapable"] is True


def test_roles_with_eligibility(graph_client, mock_graph, context):
    outcome = roles.collect(graph_client, context)
    assert outcome.data["roleEligibilityStatus"] == "ok"
    assert len(outcome.data["roleDefinitions"]) == 1
    assert len(outcome.data["roleAssignments"]) == 1
    assert len(outcome.data["roleEligibilitySchedules"]) == 1


def test_roles_marks_eligibility_unknown_when_unreadable(graph_client, mock_graph, context):
    mock_graph.get(f"{GRAPH}/v1.0/roleManagement/directory/roleEligibilitySchedules").respond(
        403, json={"error": {"code": "Authorization_RequestDenied", "message": "denied"}}
    )
    outcome = roles.collect(graph_client, context)
    assert outcome.complete is True
    assert outcome.data["roleEligibilityStatus"] == "unknown"
    assert outcome.data["roleEligibilitySchedules"] is None
    assert any("unknown" in error for error in outcome.errors)


def test_groups_counts_policy_referenced_groups(graph_client, mock_graph, context):
    context.results["conditional_access_policies"] = cap_policies.collect(graph_client, context)
    context.results["auth_methods_policy"] = auth_methods_policy.collect(graph_client, context)
    outcome = groups.collect(graph_client, context)
    assert outcome.count == 2
    assert outcome.data["transitiveMemberCounts"] == {GROUP_EXCLUDED: 5}


def test_groups_records_an_error_when_a_member_count_fails(context):
    """A failing transitive-count must not crash the collect: the group's count
    is recorded as None and the failure is captured in the outcome's errors.
    Guards the error branch of the parallelized count loop."""
    from iamai.collectors import Outcome
    from iamai.graphclient import GraphError

    gid = "40000000-0000-0000-0000-000000000009"

    class FailingCountClient:
        def get_paged(self, path, params=None, headers=None):
            return iter([{"id": gid, "displayName": "G", "groupTypes": [], "securityEnabled": True}])

        def get_count(self, path):
            raise GraphError(503, "serviceUnavailable", "throttled")

    context.results["conditional_access_policies"] = Outcome(
        endpoint="", api_version="v1.0",
        data=[{"conditions": {"users": {"includeGroups": [gid]}}}],
    )
    outcome = groups.collect(FailingCountClient(), context)
    assert outcome.data["transitiveMemberCounts"] == {gid: None}
    assert outcome.errors and gid in outcome.errors[0]


def test_service_principals(graph_client, mock_graph, context):
    outcome = service_principals.collect(graph_client, context)
    assert outcome.count == 2
    assert all("appId" in sp for sp in outcome.data)


def test_org_licenses_and_p2_detection(graph_client, mock_graph, context):
    outcome = org_licenses.collect(graph_client, context)
    assert len(outcome.data["organization"]) == 1
    assert org_licenses.has_p2(outcome.data["subscribedSkus"]) is True
    assert org_licenses.has_p2([{"servicePlans": [{"servicePlanName": "AAD_PREMIUM"}]}]) is False


def test_domains(graph_client, mock_graph, context):
    outcome = domains.collect(graph_client, context)
    assert outcome.count == 2
    assert outcome.data[0]["authenticationType"] == "Managed"


def test_signins_writes_both_feeds_as_jsonl_gz(graph_client, mock_graph, context):
    outcome = signins.collect(graph_client, context)
    assert outcome.count == 3
    interactive_path = context.writer.raw_dir / "signins_interactive.jsonl.gz"
    noninteractive_path = context.writer.raw_dir / "signins_noninteractive.jsonl.gz"
    with gzip.open(interactive_path, "rt", encoding="utf-8") as handle:
        interactive = [json.loads(line) for line in handle]
    with gzip.open(noninteractive_path, "rt", encoding="utf-8") as handle:
        noninteractive = [json.loads(line) for line in handle]
    assert len(interactive) == 2
    assert len(noninteractive) == 1
    assert interactive[0]["appliedConditionalAccessPolicies"]
    assert noninteractive[0]["signInEventTypes"] == ["nonInteractiveUser"]
    # The two feeds are queried explicitly and separately.
    beta_request = mock_graph["signins_beta"].calls[0].request
    assert "nonInteractiveUser" in unquote_plus(str(beta_request.url))
    v1_request = mock_graph["signins_v1"].calls[0].request
    assert "createdDateTime ge" in unquote_plus(str(v1_request.url))


def test_risky_users_collected_when_p2(graph_client, mock_graph, context):
    context.results["org_licenses"] = org_licenses.collect(graph_client, context)
    outcome = risky_users.collect(graph_client, context)
    assert outcome.skipped is False
    assert outcome.count == 1


def test_risky_users_skip_marker_without_p2(graph_client, mock_graph, context):
    mock_graph.get(f"{GRAPH}/v1.0/subscribedSkus").respond(
        json={"value": [{"skuId": "x", "servicePlans": [{"servicePlanName": "AAD_PREMIUM"}]}]}
    )
    context.results["org_licenses"] = org_licenses.collect(graph_client, context)
    outcome = risky_users.collect(graph_client, context)
    assert outcome.skipped is True
    assert outcome.data["skipped"] is True
    assert outcome.count == 0


def test_run_all_writes_snapshot_and_manifest(graph_client, mock_graph, tmp_path):
    writer = SnapshotStore(tmp_path / "data").new_snapshot("golden")
    manifest = run_all(graph_client, writer, "golden", days=30)
    assert manifest.complete is True
    assert len(manifest.datasets) == 16
    dataset_names = {record.dataset for record in manifest.datasets}
    assert "conditional_access_policies" in dataset_names
    assert (writer.raw_dir / "conditional_access_policies.json").exists()
    assert (writer.raw_dir / "signins_interactive.jsonl.gz").exists()
    assert (writer.snapshot_dir / "manifest.json").exists()
    for record in manifest.datasets:
        assert record.endpoint
        assert record.apiVersion
        assert record.durationSeconds >= 0


def test_run_all_marks_partial_on_collector_failure(graph_client, mock_graph, tmp_path):
    mock_graph.get(f"{GRAPH}/v1.0/domains").respond(
        403, json={"error": {"code": "Authorization_RequestDenied", "message": "denied"}}
    )
    writer = SnapshotStore(tmp_path / "data").new_snapshot("golden")
    manifest = run_all(graph_client, writer, "golden", days=30)
    assert manifest.complete is False
    domains_record = next(r for r in manifest.datasets if r.dataset == "domains")
    assert domains_record.complete is False
    assert domains_record.errors
    # The rest of the pull still happened.
    assert (writer.raw_dir / "users.json").exists()
