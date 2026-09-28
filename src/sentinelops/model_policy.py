"""Optional local-model source planning behind deterministic safety controls."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Mapping, Protocol
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinelops.audit import AuditLog
from sentinelops.domain import EvidenceSource, IncidentTask, InvestigationAction
from sentinelops.policy import HeuristicInvestigationPolicy, InvestigationState
from sentinelops.privacy import redact_private_text, scan_content


class ModelPolicyError(RuntimeError):
    """A safe, classified model-adapter failure without response content."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ModelPolicyContext(BaseModel):
    """Minimum context allowed to cross the local model boundary."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    service: str = Field(min_length=1, max_length=120)
    symptoms: list[str] = Field(min_length=1, max_length=20)
    available_sources: list[EvidenceSource] = Field(min_length=1, max_length=5)
    queried_sources: list[EvidenceSource] = Field(default_factory=list, max_length=5)
    evidence_counts: dict[EvidenceSource, int] = Field(default_factory=dict)


class ModelSourceProposal(BaseModel):
    """The only model-controlled decision: one next read-only source."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source: EvidenceSource
    rationale: str = Field(min_length=1, max_length=240)


class SourceProposer(Protocol):
    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        """Suggest one evidence source using the strict output contract."""


class _OllamaMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    content: str = Field(min_length=2, max_length=16_384)


class _OllamaChatResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    message: _OllamaMessage


_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}\Z")


@dataclass(frozen=True)
class OllamaPolicyConfig:
    model: str
    base_url: str = "http://127.0.0.1:11434"
    timeout_seconds: float = 8.0
    max_response_bytes: int = 65_536

    def __post_init__(self) -> None:
        model = self.model.strip()
        if not _MODEL_NAME.fullmatch(model):
            raise ValueError("SENTINELOPS_OLLAMA_MODEL has an invalid format")
        object.__setattr__(self, "model", model)

        base_url = self.base_url.strip().rstrip("/")
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("SENTINELOPS_OLLAMA_URL must use http or https")
        if parsed.username or parsed.password:
            raise ValueError("SENTINELOPS_OLLAMA_URL must not contain credentials")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("SENTINELOPS_OLLAMA_URL must be an origin without path or query")
        if parsed.hostname is None or not _is_loopback_host(parsed.hostname):
            raise ValueError("SENTINELOPS_OLLAMA_URL must target loopback only")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("SENTINELOPS_OLLAMA_URL has an invalid port") from exc
        if port is not None and not 1 <= port <= 65_535:
            raise ValueError("SENTINELOPS_OLLAMA_URL has an invalid port")
        object.__setattr__(self, "base_url", base_url)

        if not 0.1 <= self.timeout_seconds <= 30.0:
            raise ValueError("SENTINELOPS_OLLAMA_TIMEOUT_SECONDS must be between 0.1 and 30")
        if not 1_024 <= self.max_response_bytes <= 65_536:
            raise ValueError(
                "SENTINELOPS_OLLAMA_MAX_RESPONSE_BYTES must be between 1024 and 65536"
            )


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def ollama_policy_config_from_env(
    environment: Mapping[str, str] | None = None,
) -> OllamaPolicyConfig:
    values = os.environ if environment is None else environment
    model = values.get("SENTINELOPS_OLLAMA_MODEL", "").strip()
    if not model:
        raise ValueError("SENTINELOPS_OLLAMA_MODEL is required when policy mode is ollama")
    try:
        timeout = float(values.get("SENTINELOPS_OLLAMA_TIMEOUT_SECONDS", "8"))
        response_limit = int(values.get("SENTINELOPS_OLLAMA_MAX_RESPONSE_BYTES", "65536"))
    except ValueError as exc:
        raise ValueError("Ollama policy numeric settings must be valid numbers") from exc
    return OllamaPolicyConfig(
        model=model,
        base_url=values.get("SENTINELOPS_OLLAMA_URL", "http://127.0.0.1:11434"),
        timeout_seconds=timeout,
        max_response_bytes=response_limit,
    )


class OllamaSourceProposer:
    """Call loopback Ollama with JSON Schema output and strict response bounds."""

    def __init__(
        self,
        config: OllamaPolicyConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.config = config
        self._client = httpx.Client(
            base_url=config.base_url,
            timeout=config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    def propose(self, context: ModelPolicyContext) -> ModelSourceProposal:
        payload = {
            "model": self.config.model,
            "stream": False,
            "format": ModelSourceProposal.model_json_schema(),
            "options": {"temperature": 0},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Choose exactly one available read-only evidence source. "
                        "Do not decide finish, escalate, permissions, budgets, or query languages. "
                        "Return only JSON matching the supplied schema."
                    ),
                },
                {
                    "role": "user",
                    "content": context.model_dump_json(),
                },
            ],
        }
        try:
            with self._client.stream("POST", "/api/chat", json=payload) as response:
                response.raise_for_status()
                content_length = response.headers.get("content-length")
                if (
                    content_length is not None
                    and int(content_length) > self.config.max_response_bytes
                ):
                    raise ModelPolicyError("response_too_large")
                buffer = bytearray()
                for chunk in response.iter_bytes():
                    if len(buffer) + len(chunk) > self.config.max_response_bytes:
                        raise ModelPolicyError("response_too_large")
                    buffer.extend(chunk)
                raw = bytes(buffer)
        except ModelPolicyError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise ModelPolicyError("transport_failure") from exc

        try:
            envelope = _OllamaChatResponse.model_validate_json(raw)
            if scan_content("model-policy-response.json", envelope.message.content.encode("utf-8")):
                raise ModelPolicyError("private_output_rejected")
            return ModelSourceProposal.model_validate_json(envelope.message.content)
        except ModelPolicyError:
            raise
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise ModelPolicyError("invalid_structured_output") from exc

    def close(self) -> None:
        self._client.close()


class ControlledModelPolicy:
    """Use a model for source priority only; deterministic controls retain authority."""

    def __init__(
        self,
        proposer: SourceProposer,
        audit: AuditLog,
        *,
        allowed_sources: frozenset[EvidenceSource],
        fallback: HeuristicInvestigationPolicy | None = None,
    ) -> None:
        if not allowed_sources:
            raise ValueError("controlled model policy requires at least one allowed source")
        self.proposer = proposer
        self.audit = audit
        self.allowed_sources = allowed_sources
        self.fallback = fallback or HeuristicInvestigationPolicy()

    def decide(
        self,
        state: InvestigationState,
        *,
        trace_id: str | None = None,
    ) -> InvestigationAction:
        deterministic = self._deterministic_decision(state)
        bound_trace = trace_id or "trace-policy-unbound"
        if deterministic.source is None:
            self._audit(
                trace_id=bound_trace,
                resource=state.task.incident_id,
                status="ok",
                outcome="deterministic",
                reason_code="deterministic_terminal",
            )
            return deterministic

        available = self._available_sources(state.task, state.queried_sources)
        proposal, reason_code = self._safe_proposal(state.task, state, available)
        if proposal is None:
            self._audit(
                trace_id=bound_trace,
                resource=state.task.incident_id,
                status="degraded",
                outcome="fallback",
                reason_code=reason_code,
            )
            return deterministic

        self._audit(
            trace_id=bound_trace,
            resource=state.task.incident_id,
            status="ok",
            outcome="accepted",
            reason_code="proposal_accepted",
            source=proposal.source,
        )
        return InvestigationAction(
            action="query",
            source=proposal.source,
            keywords=self.keywords(state.task, proposal.source),
            rationale=f"controlled model prioritized read-only source: {proposal.source.value}",
        )

    def plan_sources(
        self,
        task: IncidentTask,
        *,
        allowed_sources: frozenset[EvidenceSource],
        trace_id: str,
    ) -> tuple[EvidenceSource, ...]:
        deterministic = tuple(
            source
            for source in self.fallback.source_order(task)
            if source in allowed_sources and source in self.allowed_sources
        )
        if not deterministic:
            return ()
        state = InvestigationState(task=task)
        proposal, reason_code = self._safe_proposal(task, state, deterministic)
        if proposal is None:
            self._audit(
                trace_id=trace_id,
                resource=task.incident_id,
                status="degraded",
                outcome="fallback",
                reason_code=reason_code,
            )
            return deterministic
        self._audit(
            trace_id=trace_id,
            resource=task.incident_id,
            status="ok",
            outcome="accepted",
            reason_code="proposal_accepted",
            source=proposal.source,
        )
        return (proposal.source, *(source for source in deterministic if source != proposal.source))

    def source_order(self, task: IncidentTask) -> tuple[EvidenceSource, ...]:
        return tuple(
            source for source in self.fallback.source_order(task) if source in self.allowed_sources
        )

    def keywords(self, task: IncidentTask, source: EvidenceSource) -> list[str]:
        return self.fallback.keywords(task, source)

    def _deterministic_decision(self, state: InvestigationState) -> InvestigationAction:
        decision = self.fallback.decide(state)
        if decision.source is None or decision.source in self._available_sources(
            state.task,
            state.queried_sources,
        ):
            return decision
        available = self._available_sources(state.task, state.queried_sources)
        if not available:
            return InvestigationAction(
                action="escalate",
                rationale="all allowed evidence domains queried without sufficient support",
            )
        source = available[0]
        return InvestigationAction(
            action="query",
            source=source,
            keywords=self.keywords(state.task, source),
            rationale=f"collect next allowed independent evidence domain: {source.value}",
        )

    def _available_sources(
        self,
        task: IncidentTask,
        queried_sources: set[EvidenceSource],
    ) -> tuple[EvidenceSource, ...]:
        return tuple(
            source
            for source in self.fallback.source_order(task)
            if source in self.allowed_sources and source not in queried_sources
        )

    def _safe_proposal(
        self,
        task: IncidentTask,
        state: InvestigationState,
        available_sources: tuple[EvidenceSource, ...],
    ) -> tuple[ModelSourceProposal | None, str]:
        if not available_sources:
            return None, "no_available_source"
        counts = Counter(item.source for item in state.evidence)
        context = ModelPolicyContext(
            service=redact_private_text(task.service, max_length=120),
            symptoms=[redact_private_text(item, max_length=240) for item in task.symptoms],
            available_sources=list(available_sources),
            queried_sources=sorted(state.queried_sources, key=lambda item: item.value),
            evidence_counts={source: counts[source] for source in counts},
        )
        try:
            proposed = self.proposer.propose(context)
            proposal = ModelSourceProposal.model_validate(proposed)
        except ModelPolicyError as exc:
            return None, exc.reason_code
        except ValidationError:
            return None, "invalid_structured_output"
        except Exception:
            return None, "unexpected_model_failure"
        if proposal.source not in available_sources:
            return None, "source_outside_guard"
        proposal_bytes = proposal.model_dump_json().encode("utf-8")
        if scan_content("model-source-proposal.json", proposal_bytes):
            return None, "private_output_rejected"
        return proposal, "proposal_accepted"

    def _audit(
        self,
        *,
        trace_id: str,
        resource: str,
        status: str,
        outcome: str,
        reason_code: str,
        source: EvidenceSource | None = None,
    ) -> None:
        details: dict[str, object] = {
            "outcome": outcome,
            "reason_code": reason_code,
        }
        if source is not None:
            details["source"] = source.value
        self.audit.append(
            trace_id=trace_id,
            actor="controlled-model-policy",
            action="model_source_proposed",
            resource=resource,
            status=status,
            details=details,
        )
