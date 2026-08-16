"""Groups with minimal $select, plus transitive member counts for any group
referenced by a policy.

Verified: GET /v1.0/groups (max page 999) and
GET /v1.0/groups/{id}/transitiveMembers/$count with ConsistencyLevel:
eventual (advanced query). Application permission Directory.Read.All. See
ASSUMPTIONS.md.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient, GraphError

ENDPOINT = "/groups"
API_VERSION = "v1.0"
PERMISSION = "Directory.Read.All"

# Each referenced group needs its own /$count round trip. Fetching them a few
# at a time overlaps the network latency without hammering Graph; the httpx
# client underneath is safe to call from several threads.
_COUNT_WORKERS = 8

SELECT = "id,displayName,groupTypes,securityEnabled,onPremisesSyncEnabled,membershipRule"


def _policy_referenced_group_ids(context: CollectContext) -> set[str]:
    """Group ids referenced by CAP policies, the auth methods policy, and the
    registration campaign. Needed for affected-population math."""
    referenced: set[str] = set()

    cap_outcome = context.results.get("conditional_access_policies")
    if cap_outcome and isinstance(cap_outcome.data, list):
        for policy in cap_outcome.data:
            users = (policy.get("conditions") or {}).get("users") or {}
            for key in ("includeGroups", "excludeGroups"):
                referenced.update(users.get(key) or [])

    methods_outcome = context.results.get("auth_methods_policy")
    if methods_outcome and isinstance(methods_outcome.data, dict):
        for config in methods_outcome.data.get("authenticationMethodConfigurations") or []:
            for target in config.get("includeTargets") or []:
                target_id = target.get("id")
                if target_id and target_id != "all_users":
                    referenced.add(target_id)
            for target in config.get("excludeTargets") or []:
                target_id = target.get("id")
                if target_id and target_id != "all_users":
                    referenced.add(target_id)
        campaign = (
            (methods_outcome.data.get("registrationEnforcement") or {})
            .get("authenticationMethodsRegistrationCampaign")
            or {}
        )
        for key in ("includeTargets", "excludeTargets"):
            for target in campaign.get(key) or []:
                target_id = target.get("id")
                if target_id and target_id != "all_users":
                    referenced.add(target_id)

    return referenced


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    groups = list(
        client.get_paged(f"{API_VERSION}{ENDPOINT}", params={"$select": SELECT, "$top": "999"})
    )
    group_ids = {group["id"] for group in groups if "id" in group}

    referenced = sorted(_policy_referenced_group_ids(context) & group_ids)

    def _count(group_id: str) -> tuple[str, int | None, str | None]:
        try:
            value = client.get_count(
                f"{API_VERSION}{ENDPOINT}/{group_id}/transitiveMembers/$count"
            )
            return group_id, value, None
        except GraphError as exc:
            return group_id, None, f"transitive member count failed for group {group_id}: {exc.code}"

    # Fan the counts out, then reassemble in sorted group order so the written
    # snapshot is byte identical run to run regardless of completion order.
    results: dict[str, tuple[int | None, str | None]] = {}
    if referenced:
        workers = min(_COUNT_WORKERS, len(referenced))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for group_id, value, error in pool.map(_count, referenced):
                results[group_id] = (value, error)

    member_counts: dict[str, int | None] = {gid: results[gid][0] for gid in referenced}
    errors: list[str] = [results[gid][1] for gid in referenced if results[gid][1] is not None]

    data = {"groups": groups, "transitiveMemberCounts": member_counts}
    return Outcome(
        endpoint=f"{ENDPOINT} + {ENDPOINT}/{{id}}/transitiveMembers/$count",
        api_version=API_VERSION,
        data=data,
        count=len(groups),
        errors=errors,
    )
