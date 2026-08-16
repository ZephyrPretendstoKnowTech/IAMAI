"""Directory roles: definitions, assignments, and PIM eligibility.

Verified: GET /v1.0/roleManagement/directory/roleDefinitions and
/roleAssignments accept RoleManagement.Read.Directory.
/v1.0/roleManagement/directory/roleEligibilitySchedules also accepts
RoleManagement.Read.Directory (least privileged is
RoleEligibilitySchedule.Read.Directory); when unreadable, eligibility is
marked unknown per SPEC section 4, never an error. See ASSUMPTIONS.md.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient, GraphError

ENDPOINT = "/roleManagement/directory"
API_VERSION = "v1.0"
PERMISSION = "RoleManagement.Read.Directory"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    definitions = list(client.get_paged(f"{API_VERSION}{ENDPOINT}/roleDefinitions"))
    assignments = list(client.get_paged(f"{API_VERSION}{ENDPOINT}/roleAssignments"))

    # roleAssignments carries no type or time field, so it cannot tell a
    # permanent assignment from a Privileged Identity Management activation
    # that happens to be in flight. Counting standing access from it reports
    # inflated numbers to exactly the tenants using PIM properly. The schedules
    # feed carries assignmentType (Assigned versus Activated) and scheduleInfo,
    # which is the only honest source (ASSUMPTIONS.md note 25 item j).
    schedules_status = "ok"
    schedules: list | None
    errors: list[str] = []
    try:
        schedules = list(client.get_paged(f"{API_VERSION}{ENDPOINT}/roleAssignmentSchedules"))
    except GraphError as exc:
        schedules = None
        schedules_status = "unknown"
        errors.append(f"roleAssignmentSchedules unreadable, marked unknown: {exc.code}")

    eligibility_status = "ok"
    eligibility: list | None
    try:
        eligibility = list(client.get_paged(f"{API_VERSION}{ENDPOINT}/roleEligibilitySchedules"))
    except GraphError as exc:
        eligibility = None
        eligibility_status = "unknown"
        errors.append(f"roleEligibilitySchedules unreadable, marked unknown: {exc.code}")

    data = {
        "roleDefinitions": definitions,
        "roleAssignments": assignments,
        "roleEligibilitySchedules": eligibility,
        "roleEligibilityStatus": eligibility_status,
        "roleAssignmentSchedules": schedules,
        "roleAssignmentScheduleStatus": schedules_status,
    }
    count = len(definitions) + len(assignments) + len(eligibility or []) + len(schedules or [])
    return Outcome(
        endpoint=f"{ENDPOINT}/roleDefinitions|roleAssignments|roleAssignmentSchedules|roleEligibilitySchedules",
        api_version=API_VERSION,
        data=data,
        count=count,
        errors=errors,
    )
