"""Read-only evidence access port."""

from __future__ import annotations

from typing import Protocol

from sentinelops.domain import Evidence, QuerySpec


class EvidenceTool(Protocol):
    name: str
    read_only: bool

    def query(self, spec: QuerySpec) -> list[Evidence]:
        """Return normalized evidence without mutating the source system."""
