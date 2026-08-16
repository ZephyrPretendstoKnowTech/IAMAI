"""Conditional Access policies. Full objects including state.

Verified: GET /v1.0/identity/conditionalAccess/policies, application
permission Policy.Read.All (least privileged). See ASSUMPTIONS.md.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient

ENDPOINT = "/identity/conditionalAccess/policies"
API_VERSION = "v1.0"
PERMISSION = "Policy.Read.All"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    items = list(client.get_paged(f"{API_VERSION}{ENDPOINT}"))
    return Outcome(endpoint=ENDPOINT, api_version=API_VERSION, data=items, count=len(items))
