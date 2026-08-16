"""User registration details: MFA capable and registered per user.

Verified: GET /v1.0/reports/authenticationMethods/userRegistrationDetails.
Current documentation lists AuditLog.Read.All as the application permission
for this API; Reports.Read.All stays in the manifest per SPEC section 3. See
ASSUMPTIONS.md.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient

ENDPOINT = "/reports/authenticationMethods/userRegistrationDetails"
API_VERSION = "v1.0"
PERMISSION = "Reports.Read.All"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    items = list(client.get_paged(f"{API_VERSION}{ENDPOINT}"))
    return Outcome(endpoint=ENDPOINT, api_version=API_VERSION, data=items, count=len(items))
