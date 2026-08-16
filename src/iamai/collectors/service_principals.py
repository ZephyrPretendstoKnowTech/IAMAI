"""Service principals: SP preflight data for plan steps.

Verified: GET /v1.0/servicePrincipals with $select appId, displayName,
accountEnabled. Application permission Application.Read.All. Default and
maximum page size is 100. See ASSUMPTIONS.md.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient

ENDPOINT = "/servicePrincipals"
API_VERSION = "v1.0"
PERMISSION = "Application.Read.All"

SELECT = "id,appId,displayName,accountEnabled"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    items = list(client.get_paged(f"{API_VERSION}{ENDPOINT}", params={"$select": SELECT}))
    return Outcome(endpoint=ENDPOINT, api_version=API_VERSION, data=items, count=len(items))
