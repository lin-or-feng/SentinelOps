"""Hard execution bounds for the investigation loop."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

from sentinelops.domain import InvestigationAction


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class InvestigationBudget:
    max_steps: int = 8
    max_queries: int = 6
    deadline_seconds: float = 30.0
    repeated_action_limit: int = 1
    started_at: float = field(default_factory=time.monotonic)
    steps: int = 0
    queries: int = 0
    _fingerprints: dict[str, int] = field(default_factory=dict)

    def consume(self, action: InvestigationAction) -> None:
        if time.monotonic() - self.started_at > self.deadline_seconds:
            raise BudgetExceeded("investigation deadline exceeded")
        if self.steps >= self.max_steps:
            raise BudgetExceeded("investigation step budget exceeded")
        if action.action.value == "query" and self.queries >= self.max_queries:
            raise BudgetExceeded("investigation query budget exceeded")

        payload = json.dumps(action.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
        fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        repeated = self._fingerprints.get(fingerprint, 0) + 1
        self._fingerprints[fingerprint] = repeated
        if repeated > self.repeated_action_limit:
            raise BudgetExceeded("repeated investigation action detected")

        self.steps += 1
        if action.action.value == "query":
            self.queries += 1
