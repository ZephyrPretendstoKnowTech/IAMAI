"""Admin consent workflow: whether a user asking for an app has somewhere to ask.

Verified: GET /v1.0/policies/adminConsentRequestPolicy, application permission
Policy.Read.All. It is a singleton and always present, so an unreadable
response means a permission or transport problem rather than an unconfigured
tenant.

Two surfaces describe this feature and they are not the same thing. The older
one is a directory setting named EnableAdminConsentRequests, in the Consent
Policy Settings template, readable only from beta. That template may legitimately
not exist in a tenant until something writes to it, so reading it cannot tell an
unconfigured tenant from an untouched one. This one is generally available,
always present, and also carries the reviewer list, which the directory setting
does not. See ASSUMPTIONS.md note 30.
"""

from __future__ import annotations

from iamai.collectors import CollectContext, Outcome
from iamai.graphclient import GraphClient, GraphError

ENDPOINT = "/policies/adminConsentRequestPolicy"
API_VERSION = "v1.0"
PERMISSION = "Policy.Read.All"


def collect(client: GraphClient, context: CollectContext) -> Outcome:
    errors: list[str] = []
    try:
        policy = client.get(f"{API_VERSION}{ENDPOINT}")
    except GraphError as exc:
        # Marked unknown rather than treated as absent. A tenant whose consent
        # workflow could not be read is not a tenant without one.
        policy = None
        errors.append(f"adminConsentRequestPolicy unreadable, marked unknown: {exc.code}")
    return Outcome(
        endpoint=ENDPOINT,
        api_version=API_VERSION,
        data=policy,
        count=1 if policy else 0,
        errors=errors,
    )
