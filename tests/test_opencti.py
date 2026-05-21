import json

import pytest

from azul_plugin_opencti_feed.opencti import OpenCTIClient, extract_file_hashes


def _indicator_node(**overrides):
    node = {
        "id": "indicator--1",
        "name": "Known malware",
        "description": "A sample indicator",
        "pattern": "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
        "x_opencti_score": 90,
        "confidence": 75,
        "revoked": False,
        "valid_from": "2026-01-01T00:00:00.000Z",
        "valid_until": None,
        "created_at": "2026-01-01T00:00:00.000Z",
        "updated_at": "2026-01-02T00:00:00.000Z",
        "objectLabel": {"edges": [{"node": {"value": "malware"}}]},
        "externalReferences": {"edges": [{"node": {"source_name": "report", "url": "https://example.test/report"}}]},
    }
    node.update(overrides)
    return node


def test_extract_file_hashes_from_stix_pattern():
    pattern = (
        "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] "
        "AND [file:hashes.MD5 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']"
    )

    assert extract_file_hashes(pattern) == {
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "md5": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }


def test_list_indicators_pages_through_opencti(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://opencti.example/graphql",
        json={
            "data": {
                "indicators": {
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                    "edges": [{"node": _indicator_node(id="indicator--1")}],
                }
            }
        },
    )
    httpx_mock.add_response(
        method="POST",
        url="https://opencti.example/graphql",
        json={
            "data": {
                "indicators": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [{"node": _indicator_node(id="indicator--2", name="Second malware")}],
                }
            }
        },
    )
    client = OpenCTIClient(
        base_url="https://opencti.example",
        token="secret-token",
        timeout=5,
        retry_count=0,
        page_size=1,
    )

    indicators = list(client.iter_indicators(updated_after="2026-01-01T00:00:00.000Z"))

    requests = httpx_mock.get_requests()
    assert len(requests) == 2
    assert requests[0].headers["Authorization"] == "Bearer secret-token"
    first_payload = json.loads(requests[0].content)
    second_payload = json.loads(requests[1].content)
    assert first_payload["variables"]["after"] is None
    assert first_payload["variables"]["filters"]["filters"][0]["values"] == ["2026-01-01T00:00:00.000Z"]
    assert second_payload["variables"]["after"] == "cursor-1"
    assert indicators[0].id == "indicator--1"
    assert indicators[0].sha256 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert indicators[0].labels == ["malware"]
    assert indicators[0].external_references == ["report: https://example.test/report"]
    assert indicators[1].name == "Second malware"


def test_list_indicators_raises_on_graphql_errors(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://opencti.example/graphql",
        json={"errors": [{"message": "Field does not exist"}]},
    )
    client = OpenCTIClient(
        base_url="https://opencti.example",
        token="secret-token",
        timeout=5,
        retry_count=0,
        page_size=10,
    )

    with pytest.raises(RuntimeError, match="Field does not exist"):
        list(client.iter_indicators())
