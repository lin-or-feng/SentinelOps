from sentinelops.cli import _is_loopback_host, main


def test_loopback_detection() -> None:
    assert _is_loopback_host("127.0.0.1") is True
    assert _is_loopback_host("::1") is True
    assert _is_loopback_host("localhost") is True
    assert _is_loopback_host("0.0.0.0") is False
    assert _is_loopback_host("public.example") is False


def test_serve_refuses_public_bind_without_token(monkeypatch, capsys) -> None:
    monkeypatch.delenv("SENTINELOPS_API_TOKEN", raising=False)

    exit_code = main(["serve", "--host", "0.0.0.0"])

    assert exit_code == 2
    assert "refusing non-loopback bind" in capsys.readouterr().err


def test_policy_eval_cli_runs_replay_gate(capsys) -> None:
    exit_code = main(
        [
            "policy-eval",
            "--mode",
            "replay",
            "--min-top1",
            "1",
            "--min-safety",
            "1",
            "--max-forbidden-rate",
            "0",
        ]
    )

    assert exit_code == 0
    assert '"evaluation_type": "control_plane_replay"' in capsys.readouterr().out
