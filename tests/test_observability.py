from datetime import datetime, timedelta, timezone

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from sentinelops.adapters.observability import (
    LokiEvidenceProvider,
    ObservabilityEvidenceTool,
    PrometheusEvidenceProvider,
    ProviderEndpoint,
    ProviderPayloadError,
    ResponseTooLarge,
    TempoEvidenceProvider,
    observability_tool_from_env,
)
from sentinelops.domain import EvidenceSource, IncidentStatus, IncidentTask, QuerySpec
from sentinelops.service import create_service


START = datetime(2026, 9, 27, 2, 0, tzinfo=timezone.utc)
END = START + timedelta(minutes=20)


def endpoint(host: str, **updates) -> ProviderEndpoint:
    values = {
        "base_url": f"https://{host}",
        "allowed_hosts": frozenset({host}),
        **updates,
    }
    return ProviderEndpoint(**values)


def spec(source: EvidenceSource, service: str = "order-service") -> QuerySpec:
    return QuerySpec(
        incident_id="inc-live-001",
        source=source,
        service=service,
        keywords=["this input must not become a raw provider query"],
        limit=5,
        start_time=START,
        end_time=END,
    )


def test_endpoint_requires_tls_and_exact_host_allowlist() -> None:
    with pytest.raises(ValidationError, match="plain HTTP"):
        ProviderEndpoint(
            base_url="http://metrics.internal",
            allowed_hosts=frozenset({"metrics.internal"}),
        )
    with pytest.raises(ValidationError, match="allowed_hosts"):
        ProviderEndpoint(
            base_url="https://metrics.internal",
            allowed_hosts=frozenset({"other.internal"}),
        )
    with pytest.raises(ValidationError, match="credentials"):
        ProviderEndpoint(
            base_url="https://user:" + "pass@" + "metrics.internal",
            allowed_hosts=frozenset({"metrics.internal"}),
        )


def test_prometheus_uses_bounded_template_and_normalizes_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/v1/query"
        assert request.url.params["query"] == '{service="order-service\\\"}"}'
        assert request.url.params["limit"] == "5"
        assert request.headers["authorization"] == "Bearer test-provider-token"
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        {
                            "metric": {"__name__": "db_waiting", "service": "order-service"},
                            "value": [START.timestamp(), "84"],
                        }
                    ],
                },
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = PrometheusEvidenceProvider(
        endpoint(
            "prometheus.internal",
            bearer_token=SecretStr("test-provider-token"),
        ),
        client=client,
    )

    evidence = provider.query(spec(EvidenceSource.METRICS, 'order-service"}'))

    assert len(evidence) == 1
    assert evidence[0].source == EvidenceSource.METRICS
    assert evidence[0].attributes == {"metric": "db_waiting", "value": "84"}
    assert "test-provider-token" not in evidence[0].model_dump_json()


def test_loki_redacts_private_log_content_and_bounds_results() -> None:
    private_line = "customer=" + ("138" + "0013" + "8000") + " failed with timeout"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/loki/api/v1/query_range"
        assert request.url.params["start"] == str(int(START.timestamp() * 1_000_000_000))
        assert request.url.params["direction"] == "backward"
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [
                        {
                            "stream": {"service": "order-service", "level": "error"},
                            "values": [[str(int(START.timestamp() * 1_000_000_000)), private_line]],
                        }
                    ],
                },
            },
        )

    provider = LokiEvidenceProvider(
        endpoint("loki.internal"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    evidence = provider.query(spec(EvidenceSource.LOGS))

    assert len(evidence) == 1
    assert "PRC mobile number" in evidence[0].summary
    assert private_line not in evidence[0].summary
    assert evidence[0].attributes == {"level": "error", "service": "order-service"}


def test_tempo_search_uses_bounded_window_and_normalizes_trace() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/search"
        assert request.url.params["start"] == str(int(START.timestamp()))
        assert request.url.params["end"] == str(int(END.timestamp()))
        return httpx.Response(
            200,
            json={
                "traces": [
                    {
                        "traceID": "trace-123",
                        "rootTraceName": "POST /checkout timeout",
                        "startTimeUnixNano": str(int(START.timestamp() * 1_000_000_000)),
                        "durationMs": 5000,
                    }
                ]
            },
        )

    provider = TempoEvidenceProvider(
        endpoint("tempo.internal"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    evidence = provider.query(spec(EvidenceSource.TRACES))

    assert len(evidence) == 1
    assert evidence[0].source == EvidenceSource.TRACES
    assert evidence[0].attributes["duration_ms"] == 5000
    assert evidence[0].raw_ref.endswith("/api/traces/trace-123")


def test_provider_rejects_redirect_and_large_response() -> None:
    redirecting = PrometheusEvidenceProvider(
        endpoint("prometheus.internal"),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(302, headers={"location": "https://other.internal"})
            )
        ),
    )
    with pytest.raises(ProviderPayloadError, match="redirects"):
        redirecting.query(spec(EvidenceSource.METRICS))

    oversized = PrometheusEvidenceProvider(
        endpoint("prometheus.internal", max_response_bytes=1024),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"x" * 1025)
            )
        ),
    )
    with pytest.raises(ResponseTooLarge):
        oversized.query(spec(EvidenceSource.METRICS))

    unavailable = PrometheusEvidenceProvider(
        endpoint("prometheus.internal"),
        client=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(503))
        ),
    )
    with pytest.raises(ConnectionError, match="retryable HTTP 503"):
        unavailable.query(spec(EvidenceSource.METRICS))


def test_observability_tool_routes_only_configured_sources() -> None:
    provider = PrometheusEvidenceProvider(
        endpoint("prometheus.internal"),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"status": "success", "data": {"result": []}})
            )
        ),
    )
    tool = ObservabilityEvidenceTool([provider])

    assert tool.sources == frozenset({EvidenceSource.METRICS})
    assert tool.query(spec(EvidenceSource.METRICS)) == []
    with pytest.raises(PermissionError, match="not configured"):
        tool.query(spec(EvidenceSource.LOGS))
    with pytest.raises(ValueError, match="duplicate"):
        ObservabilityEvidenceTool([provider, provider])


def test_observability_tool_closes_each_provider() -> None:
    class ClosableProvider:
        def __init__(self, source: EvidenceSource, *, fail: bool = False) -> None:
            self.source = source
            self.fail = fail
            self.closed = False

        def query(self, query_spec):
            return []

        def close(self) -> None:
            self.closed = True
            if self.fail:
                raise OSError("close failed")

    failing_provider = ClosableProvider(EvidenceSource.LOGS, fail=True)
    healthy_provider = ClosableProvider(EvidenceSource.METRICS)
    tool = ObservabilityEvidenceTool([failing_provider, healthy_provider])

    with pytest.raises(RuntimeError, match="failed to close"):
        tool.close()

    assert failing_provider.closed is True
    assert healthy_provider.closed is True


def test_environment_factory_requires_allowlist_and_builds_selected_providers() -> None:
    with pytest.raises(ValueError, match="ALLOWED_OBSERVABILITY_HOSTS"):
        observability_tool_from_env({"SENTINELOPS_PROMETHEUS_URL": "https://metrics.internal"})

    tool = observability_tool_from_env(
        {
            "SENTINELOPS_ALLOWED_OBSERVABILITY_HOSTS": "metrics.internal,logs.internal",
            "SENTINELOPS_PROMETHEUS_URL": "https://metrics.internal",
            "SENTINELOPS_LOKI_URL": "https://logs.internal",
        }
    )
    assert tool.sources == frozenset({EvidenceSource.METRICS, EvidenceSource.LOGS})


def test_live_providers_complete_the_bounded_agent_flow(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "prometheus.internal":
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "metric": {"__name__": "db_waiting"},
                                "value": [START.timestamp(), "84"],
                            }
                        ]
                    },
                },
            )
        if request.url.host == "loki.internal":
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "stream": {"service": "order-service", "level": "error"},
                                "values": [
                                    [
                                        str(int(START.timestamp() * 1_000_000_000)),
                                        "pool timeout while acquiring a database connection",
                                    ]
                                ],
                            }
                        ]
                    },
                },
            )
        return httpx.Response(
            200,
            json={
                "traces": [
                    {
                        "traceID": "trace-db-live",
                        "rootTraceName": "database connection pool wait timeout",
                        "startTimeUnixNano": str(int(START.timestamp() * 1_000_000_000)),
                        "durationMs": 4800,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    tool = ObservabilityEvidenceTool(
        [
            PrometheusEvidenceProvider(endpoint("prometheus.internal"), client=client),
            LokiEvidenceProvider(endpoint("loki.internal"), client=client),
            TempoEvidenceProvider(endpoint("tempo.internal"), client=client),
        ]
    )
    service = create_service(
        evidence_tool=tool,
        db_path=tmp_path / "live.db",
        audit_key="test-live-audit-key",
    )
    task = IncidentTask(
        incident_id="inc-live-database",
        tenant_id="demo",
        service="order-service",
        started_at=START,
        symptoms=["Requests wait and then fail"],
    )

    result = service.investigate(task)

    assert result.report.status == IncidentStatus.DIAGNOSED
    assert result.report.selected_code == "database_pool_exhaustion"
    assert result.report.tool_queries == 3
    assert len(result.report.evidence_ids) == 3
    assert service.audit.verify().valid is True


def test_query_spec_requires_bounded_ordered_window() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        QuerySpec(
            incident_id="inc-window",
            source=EvidenceSource.LOGS,
            start_time=datetime(2026, 9, 27, 2, 0),
            end_time=datetime(2026, 9, 27, 2, 5),
        )
    with pytest.raises(ValidationError, match="provided together"):
        QuerySpec(
            incident_id="inc-window",
            source=EvidenceSource.LOGS,
            start_time=START,
        )
    with pytest.raises(ValidationError, match="earlier"):
        QuerySpec(
            incident_id="inc-window",
            source=EvidenceSource.LOGS,
            start_time=END,
            end_time=START,
        )
    with pytest.raises(ValidationError, match="one hour"):
        QuerySpec(
            incident_id="inc-window",
            source=EvidenceSource.LOGS,
            start_time=START,
            end_time=START + timedelta(hours=2),
        )
