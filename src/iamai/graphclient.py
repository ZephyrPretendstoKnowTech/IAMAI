"""Microsoft Graph client.

App-only access with a certificate credential via MSAL. httpx for transport,
tenacity for retry with exponential backoff, Retry-After honored on 429/503.
Requests are restricted to graph.microsoft.com; token acquisition goes only to
login.microsoftonline.com. Tokens and Authorization headers are never logged.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from tenacity import retry, retry_if_exception_type, stop_after_attempt
from tenacity.wait import wait_base

GRAPH_HOST = "graph.microsoft.com"
GRAPH_BASE = f"https://{GRAPH_HOST}"
LOGIN_HOST = "login.microsoftonline.com"
GRAPH_SCOPE = f"{GRAPH_BASE}/.default"

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 6


_BEARER_RE = re.compile(r"(?i)bearer\s+\S+")
_JWT_RE = re.compile(r"\b[\w-]{20,}\.[\w-]{20,}\.[\w-]*\b")


def redact(text: str) -> str:
    """Strip bearer tokens and JWT-shaped strings from any text destined for
    logs or errors."""
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    return _JWT_RE.sub("[REDACTED]", text)


class GraphError(Exception):
    """A non-retryable Graph API error. Carries no headers or tokens."""

    def __init__(self, status_code: int, code: str, message: str):
        self.status_code = status_code
        self.code = code
        # Redacted here, not just in the string passed to Exception.__init__,
        # so every accessor -- str(exc), exc.message, and any future one -- is
        # safe by construction. cli.py already reads exc.message directly for
        # a substring check, proving that accessor gets used; the class
        # docstring's promise that this carries no headers or tokens used to
        # hold only for str(exc) (SECRETS-002).
        self.message = redact(message)
        super().__init__(f"Graph request failed ({status_code} {code}): {self.message}")


class GraphAuthError(Exception):
    """Token acquisition failed."""


class _RetryableStatusError(GraphError):
    """Raised while retrying, and re-raised when the attempts run out.

    It subclasses GraphError so that a collector's graceful-degradation
    handler catches it. Previously exhausting the retries on a throttled
    sub-call escaped every handler and discarded the whole dataset, including
    data already fetched, which degraded worst on exactly the large tenants
    where throttling is expected (BUGS.md item 19)."""

    def __init__(self, status_code: int, retry_after: float | None):
        self.retry_after = retry_after
        super().__init__(
            status_code,
            "retryableStatus",
            "The server kept returning a retryable status and the attempts ran out.",
        )


_MAX_RETRY_AFTER = 60.0


def _parse_retry_after(header: str | None) -> float | None:
    """Retry-After as seconds, capped.

    RFC 9110 permits an HTTP date as well as a delay in seconds, and float()
    on the date form raised out of the request and killed the dataset. The cap
    matters too: an uncapped honoured value slept for as long as the server
    asked, with no output (BUGS.md item 21)."""
    if not header:
        return None
    try:
        seconds = float(header)
    except ValueError:
        from email.utils import parsedate_to_datetime

        try:
            target = parsedate_to_datetime(header)
        except (TypeError, ValueError):
            return None
        if target is None:
            return None
        import datetime as _dt

        now = _dt.datetime.now(_dt.timezone.utc)
        if target.tzinfo is None:
            target = target.replace(tzinfo=_dt.timezone.utc)
        seconds = (target - now).total_seconds()
    return max(0.0, min(seconds, _MAX_RETRY_AFTER))


class _RetryAfterOrExponential(wait_base):
    """Honor Retry-After when the server sent one, else exponential backoff."""

    def __init__(self, backoff_base: float):
        self.backoff_base = backoff_base

    def __call__(self, retry_state) -> float:
        exc = retry_state.outcome.exception() if retry_state.outcome else None
        if isinstance(exc, _RetryableStatusError) and exc.retry_after is not None:
            return exc.retry_after
        return min(self.backoff_base * (2 ** (retry_state.attempt_number - 1)), 60.0)


def load_certificate(cert_path: Path) -> tuple[str, str]:
    """Load the PEM file holding the private key and certificate.

    Returns (private_key_pem, sha1_thumbprint_hex) as MSAL expects.
    """
    pem_bytes = cert_path.read_bytes()
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    certificate = x509.load_pem_x509_certificate(pem_bytes)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    thumbprint = certificate.fingerprint(hashes.SHA1()).hex()
    return key_pem, thumbprint


class GraphClient:
    """App-only Graph client for one tenant."""

    def __init__(
        self,
        tenant_id: str,
        app_id: str | None = None,
        cert_path: Path | None = None,
        token_provider: Callable[[], str] | None = None,
        http_client: httpx.Client | None = None,
        backoff_base: float = 1.0,
    ):
        self.tenant_id = tenant_id
        self._app_id = app_id
        self._cert_path = cert_path
        self._token_provider = token_provider
        # Read timeout must exceed Graph's own ~120s gateway limit: signIns
        # pages were measured at 60-120s server-side on a live tenant, and a
        # tighter client timeout turns slow successes and retryable 504s into
        # opaque ReadTimeouts (ASSUMPTIONS.md note 19).
        self._http = http_client or httpx.Client(
            timeout=httpx.Timeout(180.0, connect=15.0)
        )
        self._msal_app = None
        self._wait = _RetryAfterOrExponential(backoff_base)

    def _build_msal_app(self):
        import msal

        if self._app_id is None or self._cert_path is None:
            raise GraphAuthError("No credentials configured and no token provider given.")
        key_pem, thumbprint = load_certificate(self._cert_path)
        return msal.ConfidentialClientApplication(
            client_id=self._app_id,
            authority=f"https://{LOGIN_HOST}/{self.tenant_id}",
            client_credential={"private_key": key_pem, "thumbprint": thumbprint},
        )

    def _token(self) -> str:
        if self._token_provider is not None:
            return self._token_provider()
        if self._msal_app is None:
            self._msal_app = self._build_msal_app()
        result = self._msal_app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
        if "access_token" not in result:
            error = result.get("error", "unknown_error")
            description = result.get("error_description", "")
            raise GraphAuthError(f"Token acquisition failed: {error}. {redact(description)}")
        return result["access_token"]

    def _resolve_url(self, path: str) -> str:
        if path.startswith("https://"):
            url = path
        else:
            url = f"{GRAPH_BASE}/{path.lstrip('/')}"
        host = urlparse(url).hostname
        if host != GRAPH_HOST:
            raise GraphError(0, "blocked_host", f"Refusing request to non-Graph host: {host}")
        return url

    def _request_once(self, url: str, params: dict | None, headers: dict | None) -> httpx.Response:
        request_headers = {"Authorization": f"Bearer {self._token()}"}
        if headers:
            request_headers.update(headers)
        try:
            response = self._http.get(url, params=params, headers=request_headers)
        except httpx.TransportError:
            raise
        if response.status_code in _RETRYABLE_STATUS:
            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
            raise _RetryableStatusError(response.status_code, retry_after)
        if response.status_code >= 400:
            code, message = self._parse_error(response)
            raise GraphError(response.status_code, code, message)
        return response

    @staticmethod
    def _parse_error(response: httpx.Response) -> tuple[str, str]:
        try:
            error = response.json().get("error", {})
            return error.get("code", "unknown"), error.get("message", response.text[:500])
        except Exception:
            return "unknown", response.text[:500]

    def _request(self, url: str, params: dict | None = None, headers: dict | None = None) -> httpx.Response:
        retryer = retry(
            retry=retry_if_exception_type((_RetryableStatusError, httpx.TransportError)),
            stop=stop_after_attempt(_MAX_ATTEMPTS),
            wait=self._wait,
            sleep=time.sleep,
            reraise=True,
        )
        return retryer(self._request_once)(url, params, headers)

    def get(self, path: str, params: dict | None = None, headers: dict | None = None) -> dict:
        """GET a single resource and return the parsed JSON body."""
        return self._request(self._resolve_url(path), params, headers).json()

    def get_count(self, path: str) -> int:
        """GET a /$count endpoint (text/plain). Sends ConsistencyLevel: eventual."""
        response = self._request(self._resolve_url(path), None, {"ConsistencyLevel": "eventual"})
        return int(response.text.strip())

    def get_paged(
        self,
        path: str,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> Iterator[dict]:
        """GET a collection, following @odata.nextLink until exhausted."""
        url: str | None = self._resolve_url(path)
        first = True
        # A self-referential or cycling nextLink used to loop forever, and
        # inside the sign-in streamer it wrote unbounded data to disk
        # (BUGS.md item 22).
        seen: set[str] = set()
        while url:
            if url in seen:
                raise GraphError(
                    0,
                    "pagingLoop",
                    "The server returned a next page link it had already sent, "
                    "so paging was stopped to avoid looping forever.",
                )
            seen.add(url)
            body = self._request(url, params if first else None, headers).json()
            yield from body.get("value", [])
            next_link = body.get("@odata.nextLink")
            url = self._resolve_url(next_link) if next_link else None
            first = False
