"""OpenCTI GraphQL feed client helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

import httpx

HASH_PATTERN = re.compile(
    r"file:hashes\.('?)(?P<algorithm>SHA-256|SHA-1|MD5)\1\s*=\s*'(?P<value>[A-Fa-f0-9]+)'",
    re.IGNORECASE,
)
HASH_KEYS = {
    "SHA-256": "sha256",
    "SHA-1": "sha1",
    "MD5": "md5",
}


class OpenCTIError(RuntimeError):
    """Raised when OpenCTI returns a GraphQL-level error."""


@dataclass(frozen=True)
class OpenCTIIndicator:
    """A normalized OpenCTI indicator containing file hash metadata."""

    id: str
    name: str
    pattern: str
    description: str = ""
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    score: int | None = None
    confidence: int | None = None
    revoked: bool | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    labels: list[str] = field(default_factory=list)
    external_references: list[str] = field(default_factory=list)


def extract_file_hashes(pattern: str) -> dict[str, str]:
    """Extract supported file hashes from an OpenCTI STIX indicator pattern."""
    hashes: dict[str, str] = {}
    for match in HASH_PATTERN.finditer(pattern or ""):
        key = HASH_KEYS.get(match.group("algorithm").upper())
        if key:
            hashes[key] = match.group("value").lower()
    return hashes


class OpenCTIClient:
    """Small GraphQL client for streaming OpenCTI indicators into Azul."""

    INDICATOR_QUERY = """
    query AzulOpenCTIFeedIndicators($first: Int, $after: ID, $filters: FilterGroup) {
      indicators(first: $first, after: $after, filters: $filters, orderBy: updated_at, orderMode: asc) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          node {
            id
            name
            description
            pattern
            x_opencti_score
            confidence
            revoked
            valid_from
            valid_until
            created_at
            updated_at
            objectLabel {
              edges {
                node {
                  value
                }
              }
            }
            externalReferences {
              edges {
                node {
                  source_name
                  url
                }
              }
            }
          }
        }
      }
    }
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        timeout: int | float,
        retry_count: int,
        page_size: int,
    ) -> None:
        self.base_url = str(httpx.URL(base_url)).rstrip("/")
        self.page_size = int(page_size)
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            transport=httpx.HTTPTransport(retries=int(retry_count)),
            timeout=timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self.client.close()

    def __enter__(self) -> "OpenCTIClient":
        """Return the client for context manager use."""
        return self

    def __exit__(self, *args: object) -> None:
        """Close the underlying HTTP client on context manager exit."""
        self.close()

    def iter_indicators(self, updated_after: str | None = None) -> Iterator[OpenCTIIndicator]:
        """Yield OpenCTI indicators updated after the supplied state value."""
        after = None
        while True:
            response = self.client.post(
                "/graphql",
                json={
                    "query": self.INDICATOR_QUERY,
                    "variables": {
                        "first": self.page_size,
                        "after": after,
                        "filters": self._updated_after_filter(updated_after),
                    },
                },
            )
            response.raise_for_status()
            payload = response.json()
            if errors := payload.get("errors"):
                messages = ", ".join(str(error.get("message", error)) for error in errors)
                raise OpenCTIError(messages)

            connection = (payload.get("data") or {}).get("indicators") or {}
            for node in self._edge_nodes(connection):
                yield self._parse_indicator(node)

            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")

    @staticmethod
    def _updated_after_filter(updated_after: str | None) -> dict[str, Any]:
        filters = []
        if updated_after:
            filters.append(
                {
                    "key": "updated_at",
                    "values": [updated_after],
                    "operator": "gt",
                    "mode": "or",
                }
            )
        return {"mode": "and", "filters": filters, "filterGroups": []}

    @staticmethod
    def _edge_nodes(connection: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not connection:
            return []
        return [edge.get("node") or {} for edge in connection.get("edges") or []]

    @classmethod
    def _labels(cls, node: dict[str, Any]) -> list[str]:
        return sorted(
            label.get("value", "") for label in cls._edge_nodes(node.get("objectLabel")) if label.get("value")
        )

    @classmethod
    def _external_references(cls, node: dict[str, Any]) -> list[str]:
        refs = []
        for ref in cls._edge_nodes(node.get("externalReferences")):
            source = ref.get("source_name")
            url = ref.get("url")
            if source and url:
                refs.append(f"{source}: {url}")
            elif source:
                refs.append(source)
            elif url:
                refs.append(url)
        return sorted(refs)

    @classmethod
    def _parse_indicator(cls, node: dict[str, Any]) -> OpenCTIIndicator:
        hashes = extract_file_hashes(node.get("pattern", ""))
        return OpenCTIIndicator(
            id=node.get("id", ""),
            name=node.get("name", ""),
            description=node.get("description") or "",
            pattern=node.get("pattern", ""),
            sha256=hashes.get("sha256", ""),
            sha1=hashes.get("sha1", ""),
            md5=hashes.get("md5", ""),
            score=node.get("x_opencti_score"),
            confidence=node.get("confidence"),
            revoked=node.get("revoked"),
            valid_from=node.get("valid_from"),
            valid_until=node.get("valid_until"),
            created_at=node.get("created_at"),
            updated_at=node.get("updated_at"),
            labels=cls._labels(node),
            external_references=cls._external_references(node),
        )
