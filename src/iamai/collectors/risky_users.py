"""Risky users, collected only when an Entra ID P2 license is detected.

Verified: GET /v1.0/identityProtection/riskyUsers, application permission
IdentityRiskyUser.Read.All, requires a Microsoft Entra ID P2 license. Without
P2 a skip marker is written, never an error. See ASSUMPTIONS.md.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.collectors.org_licenses import has_p2
from iamai.graphclient import GraphClient

ENDPOINT = "/identityProtection/riskyUsers"
API_VERSION = "v1.0"
PERMISSION = "IdentityRiskyUser.Read.All"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    licenses_outcome = context.results.get("org_licenses")
    skus = []
    if licenses_outcome and isinstance(licenses_outcome.data, dict):
        skus = licenses_outcome.data.get("subscribedSkus") or []

    if not has_p2(skus):
        # Saying P2 was "not detected" claims the licences were read. When the
        # licence pull itself failed they were not, and the tool must not
        # assert a fact about the tenant it never checked (BUGS.md item 35).
        reason = (
            "Entra ID P2 not detected in subscribed SKUs; risky users not collected."
            if skus
            else "The tenant's licences could not be read, so whether Entra ID P2 "
                 "is present is unknown; risky users not collected."
        )
        marker = {"skipped": True, "reason": reason}
        return Outcome(
            endpoint=ENDPOINT,
            api_version=API_VERSION,
            data=marker,
            count=0,
            skipped=True,
        )

    items = list(client.get_paged(f"{API_VERSION}{ENDPOINT}"))
    return Outcome(endpoint=ENDPOINT, api_version=API_VERSION, data=items, count=len(items))
