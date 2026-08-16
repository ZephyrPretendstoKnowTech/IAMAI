"""Shared test plumbing.

All tests run against respx-mocked Graph responses recorded in
tests/fixtures/ (sanitized snapshots only). assert_all_mocked guarantees zero
live network calls; the Graph client gets an injected token provider so MSAL
is never invoked.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from iamai.graphclient import GraphClient

FIXTURES = Path(__file__).parent / "fixtures"
GRAPH = "https://graph.microsoft.com"

TENANT_ID = "11111111-1111-1111-1111-111111111111"
APP_ID = "f0000000-0000-0000-0000-00000000000f"
USER_1 = "20000000-0000-0000-0000-000000000001"
GROUP_EXCLUDED = "30000000-0000-0000-0000-000000000001"


def fx(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def make_test_client() -> GraphClient:
    return GraphClient(tenant_id=TENANT_ID, token_provider=lambda: "test-token", backoff_base=0)


@pytest.fixture
def graph_client() -> GraphClient:
    return make_test_client()


def register_graph_routes(router: respx.MockRouter) -> None:
    router.get(f"{GRAPH}/v1.0/identity/conditionalAccess/policies").respond(
        json=fx("cap_policies.json")
    )
    router.get(f"{GRAPH}/v1.0/identity/conditionalAccess/namedLocations").respond(
        json=fx("named_locations.json")
    )
    router.get(f"{GRAPH}/v1.0/policies/authenticationStrengthPolicies").respond(
        json=fx("auth_strengths.json")
    )
    router.get(f"{GRAPH}/v1.0/policies/authenticationMethodsPolicy").respond(
        json=fx("auth_methods_policy.json")
    )
    router.get(f"{GRAPH}/v1.0/policies/identitySecurityDefaultsEnforcementPolicy").respond(
        json=fx("security_defaults.json")
    )
    router.get(f"{GRAPH}/v1.0/policies/authorizationPolicy").respond(
        json=fx("authorization_policy.json")
    )
    router.get(f"{GRAPH}/v1.0/policies/adminConsentRequestPolicy").respond(
        json=fx("admin_consent_request_policy.json")
    )
    def users_responder(request):
        page = "users_page2.json" if "skiptoken" in str(request.url) else "users_page1.json"
        return httpx.Response(200, json=fx(page))

    router.get(f"{GRAPH}/v1.0/users", name="users").mock(side_effect=users_responder)
    router.get(f"{GRAPH}/v1.0/users/{USER_1}/authentication/methods").respond(
        json=fx("auth_methods_user.json")
    )
    router.get(
        f"{GRAPH}/v1.0/reports/authenticationMethods/userRegistrationDetails"
    ).respond(json=fx("registration_details.json"))
    def role_definitions_responder(request):
        # Real Graph rejects $top on this endpoint (only $filter/$expand supported).
        if "$top" in request.url.params:
            return httpx.Response(400, json={"error": {
                "code": "Request_UnsupportedQuery",
                "message": "Unsupported query parameter: $top",
            }})
        return httpx.Response(200, json=fx("role_definitions.json"))

    router.get(f"{GRAPH}/v1.0/roleManagement/directory/roleDefinitions").mock(
        side_effect=role_definitions_responder
    )
    router.get(f"{GRAPH}/v1.0/roleManagement/directory/roleAssignments").respond(
        json=fx("role_assignments.json")
    )
    router.get(f"{GRAPH}/v1.0/roleManagement/directory/roleAssignmentSchedules").respond(
        json=fx("role_assignment_schedules.json")
    )
    router.get(f"{GRAPH}/v1.0/roleManagement/directory/roleEligibilitySchedules").respond(
        json=fx("role_eligibility.json")
    )
    router.get(f"{GRAPH}/v1.0/groups").respond(json=fx("groups.json"))
    router.get(f"{GRAPH}/v1.0/groups/{GROUP_EXCLUDED}/transitiveMembers/$count").respond(
        text="5"
    )
    router.get(f"{GRAPH}/v1.0/servicePrincipals").respond(json=fx("service_principals.json"))
    router.get(f"{GRAPH}/v1.0/organization").respond(json=fx("organization.json"))
    router.get(f"{GRAPH}/v1.0/subscribedSkus").respond(json=fx("subscribed_skus.json"))
    router.get(f"{GRAPH}/v1.0/domains").respond(json=fx("domains.json"))
    def signins_responder(fixture_name):
        # Live Graph 504s on this endpoint without an explicit $top
        # (observed 2026-07-02, ASSUMPTIONS.md note 19).
        def responder(request):
            if "$top" not in request.url.params:
                return httpx.Response(504, json={"error": {
                    "code": "UnknownError",
                    "message": "Gateway Timeout",
                }})
            # The collector pulls one-day [ge, lt) slices with the newest
            # slice unbounded above. Serve the fixture on the unbounded
            # slice (and on verify's unfiltered probe); bounded slices get
            # an empty page, keeping repeated collects deterministic.
            if "createdDateTime lt" in request.url.params.get("$filter", ""):
                return httpx.Response(200, json={"value": []})
            return httpx.Response(200, json=fx(fixture_name))
        return responder

    router.get(f"{GRAPH}/v1.0/auditLogs/signIns", name="signins_v1").mock(
        side_effect=signins_responder("signins_interactive.json")
    )
    router.get(f"{GRAPH}/beta/auditLogs/signIns", name="signins_beta").mock(
        side_effect=signins_responder("signins_noninteractive.json")
    )
    router.get(f"{GRAPH}/v1.0/identityProtection/riskyUsers").respond(
        json=fx("risky_users.json")
    )


@pytest.fixture
def mock_graph():
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        register_graph_routes(router)
        yield router


@pytest.fixture
def graph_mock():
    """Empty strict router for tests that register their own routes."""
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router
