"""Domains: isVerified and authenticationType (managed vs federated).

Verified: GET /v1.0/domains, application permission Domain.Read.All. See
ASSUMPTIONS.md.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient

ENDPOINT = "/domains"
API_VERSION = "v1.0"
PERMISSION = "Domain.Read.All"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    items = list(client.get_paged(f"{API_VERSION}{ENDPOINT}"))
    return Outcome(endpoint=ENDPOINT, api_version=API_VERSION, data=items, count=len(items))
