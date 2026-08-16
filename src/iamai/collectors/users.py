"""Users, paged fully, with sign-in activity.

Verified: GET /v1.0/users with $select. signInActivity requires the
AuditLog.Read.All application permission and an Entra ID P1 or P2 license;
when signInActivity is selected the maximum page size is 500. See
ASSUMPTIONS.md.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient

ENDPOINT = "/users"
API_VERSION = "v1.0"
PERMISSION = "Directory.Read.All"

SELECT = (
    "id,accountEnabled,userType,userPrincipalName,displayName,"
    "onPremisesSyncEnabled,signInActivity"
)


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    items = list(
        client.get_paged(f"{API_VERSION}{ENDPOINT}", params={"$select": SELECT, "$top": "500"})
    )
    return Outcome(endpoint=ENDPOINT, api_version=API_VERSION, data=items, count=len(items))
