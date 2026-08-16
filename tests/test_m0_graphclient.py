from urllib.parse import unquote_plus

import httpx
import pytest

from iamai.graphclient import GraphError, redact

from conftest import GRAPH, make_test_client

pytestmark = pytest.mark.m0


def test_get_paged_follows_next_link(graph_mock):
    page1 = {
        "value": [{"id": "a"}, {"id": "b"}],
        "@odata.nextLink": f"{GRAPH}/v1.0/things?$skiptoken=t2",
    }
    page2 = {"value": [{"id": "c"}]}
    route = graph_mock.get(f"{GRAPH}/v1.0/things").mock(
        side_effect=[httpx.Response(200, json=page1), httpx.Response(200, json=page2)]
    )
    items = list(make_test_client().get_paged("v1.0/things", params={"$top": "2"}))
    assert [item["id"] for item in items] == ["a", "b", "c"]
    assert route.call_count == 2
    # Original params go only on the first request; nextLink carries its own.
    assert "$top" in unquote_plus(str(route.calls[0].request.url))
    assert "$skiptoken" in unquote_plus(str(route.calls[1].request.url))


def test_429_honors_retry_after_then_succeeds(graph_mock):
    route = graph_mock.get(f"{GRAPH}/v1.0/things").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"value": []}),
        ]
    )
    body = make_test_client().get("v1.0/things")
    assert body == {"value": []}
    assert route.call_count == 2


def test_5xx_retried_with_backoff(graph_mock):
    route = graph_mock.get(f"{GRAPH}/v1.0/things").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(500),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    assert make_test_client().get("v1.0/things") == {"ok": True}
    assert route.call_count == 3


def test_4xx_raises_graph_error_with_code(graph_mock):
    graph_mock.get(f"{GRAPH}/v1.0/things").respond(
        403,
        json={"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
    )
    with pytest.raises(GraphError) as excinfo:
        make_test_client().get("v1.0/things")
    assert excinfo.value.status_code == 403
    assert excinfo.value.code == "Authorization_RequestDenied"


def test_non_graph_host_is_blocked():
    with pytest.raises(GraphError, match="blocked_host"):
        make_test_client().get("https://example.com/v1.0/things")


def test_get_count_sends_consistency_level(graph_mock):
    route = graph_mock.get(f"{GRAPH}/v1.0/groups/x/transitiveMembers/$count").respond(text="42")
    assert make_test_client().get_count("v1.0/groups/x/transitiveMembers/$count") == 42
    assert route.calls[0].request.headers["ConsistencyLevel"] == "eventual"


def test_errors_never_contain_bearer_tokens(graph_mock):
    graph_mock.get(f"{GRAPH}/v1.0/things").respond(
        400, json={"error": {"code": "x", "message": "Authorization: Bearer abc.def.ghi failed"}}
    )
    with pytest.raises(GraphError) as excinfo:
        make_test_client().get("v1.0/things")
    assert "abc.def.ghi" not in str(excinfo.value)


def test_redact_strips_token_like_strings():
    token = "eyJ" + "a" * 60 + "." + "b" * 60 + "." + "c" * 60
    assert token not in redact(f"failed with header {token} attached")
    assert "Bearer xyz" not in redact("Authorization: Bearer xyz123")


def test_graph_error_message_attribute_is_redacted_not_just_str():
    """GraphError used to redact only the string passed to Exception.__init__,
    so str(exc) was safe but the raw pre-redaction text sat on self.message.
    cli.py reads exc.message directly for a substring check, so that accessor
    is not theoretical -- a future call site that prints .message instead of
    str(exc) would defeat redact() entirely (SECRETS-002)."""
    token = "eyJ" + "a" * 60 + "." + "b" * 60 + "." + "c" * 60
    exc = GraphError(500, "serverError", f"failed with header {token} attached")
    assert token not in exc.message
    assert token not in str(exc)
