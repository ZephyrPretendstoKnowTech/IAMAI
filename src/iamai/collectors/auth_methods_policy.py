"""Authentication methods policy.

Per-method configuration (automatically expanded on GET), includeTargets, and
registrationEnforcement (the registration campaign lives here).

Verified: GET /v1.0/policies/authenticationMethodsPolicy, application
permission Policy.Read.All. See ASSUMPTIONS.md.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient

ENDPOINT = "/policies/authenticationMethodsPolicy"
API_VERSION = "v1.0"
PERMISSION = "Policy.Read.All"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    policy = client.get(f"{API_VERSION}{ENDPOINT}")
    return Outcome(endpoint=ENDPOINT, api_version=API_VERSION, data=policy, count=1)
