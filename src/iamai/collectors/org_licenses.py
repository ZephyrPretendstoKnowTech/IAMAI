"""Organization metadata and subscribed SKUs for license gating.

Verified: GET /v1.0/organization and GET /v1.0/subscribedSkus, application
permission Organization.Read.All. See ASSUMPTIONS.md.

P2 detection: the AAD_PREMIUM_P2 service plan id is a Microsoft universal
constant and is never transformed by the sanitizer.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient

ENDPOINT = "/organization + /subscribedSkus"
API_VERSION = "v1.0"
PERMISSION = "Organization.Read.All"

AAD_PREMIUM_P2_SERVICE_PLAN_ID = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
AAD_PREMIUM_P2_SERVICE_PLAN_NAME = "AAD_PREMIUM_P2"


def has_p2(subscribed_skus: list[dict]) -> bool:
    for sku in subscribed_skus:
        for plan in sku.get("servicePlans") or []:
            if (
                plan.get("servicePlanId") == AAD_PREMIUM_P2_SERVICE_PLAN_ID
                or plan.get("servicePlanName") == AAD_PREMIUM_P2_SERVICE_PLAN_NAME
            ):
                return True
    return False


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    organization = list(client.get_paged(f"{API_VERSION}/organization"))
    skus = list(client.get_paged(f"{API_VERSION}/subscribedSkus"))
    data = {"organization": organization, "subscribedSkus": skus}
    return Outcome(
        endpoint=ENDPOINT,
        api_version=API_VERSION,
        data=data,
        count=len(organization) + len(skus),
    )
