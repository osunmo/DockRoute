import json

import pytest
from test_core import node
from test_probe_v02 import StageClient

from dockroute import cli


@pytest.mark.parametrize("command", ["doctor", "check"])
def test_cli_defaults_separate_network_deadlines_and_conditional_scheduling(command):
    arguments = [command] + (["app", "api:8000"] if command == "check" else [])
    args = cli.parser().parse_args(arguments)
    assert args.timeout == 5
    assert args.dns_timeout == 2
    assert args.connect_timeout == 1
    assert args.schedule == "conditional"


def test_cli_accepts_explicit_network_deadlines_and_sequential_comparison():
    args = cli.parser().parse_args(
        ["doctor", "--dns-timeout", "0.5", "--connect-timeout", "0.25", "--schedule", "sequential"]
    )
    assert args.dns_timeout == 0.5 and args.connect_timeout == 0.25
    assert args.schedule == "sequential"


@pytest.mark.parametrize("option", ["--dns-timeout", "--connect-timeout"])
@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "61"])
def test_cli_rejects_invalid_network_deadlines(option, value):
    with pytest.raises(SystemExit) as exc:
        cli.parser().parse_args(["doctor", option, value])
    assert exc.value.code == 4


def test_cli_network_deadlines_reach_real_prober_and_report(monkeypatch, capsys):
    class Inspector:
        client = StageClient()

        def identities(self):
            return [node("app"), node("api")]

        def snapshot(self, project):
            return [node("app", env={"UPSTREAM_URL": "http://api:8000"}), node("api")]

        def version(self):
            return {"Version": "29.0.0", "Os": "linux"}

        def close(self):
            pass

    monkeypatch.setattr(cli, "connect", lambda **kwargs: Inspector())
    assert (
        cli.main(
            [
                "doctor",
                "--project",
                "shop",
                "--probe",
                "--format",
                "json",
                "--dns-timeout",
                "0.5",
                "--connect-timeout",
                "0.25",
            ]
        )
        == 0
    )
    observed = json.loads(capsys.readouterr().out)["findings"][0]["probe"]
    assert observed["dns_timeout"] == 0.5 and observed["connect_timeout"] == 0.25
    assert observed["listener_skipped"] is True
