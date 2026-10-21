import json
from pathlib import Path

import jsonschema
import pytest
from test_core import node

from dockroute.diagnostics import diagnose
from dockroute.models import Connection
from dockroute.reporting import make_report, render_json


def test_emitted_report_and_error_conform_to_published_contract():
    schema = json.loads(Path("docs/report.schema.json").read_text())
    containers = [node("app"), node("api")]
    report = make_report(
        "shop", containers, [diagnose(Connection("app-id", "app", "api", 8000), containers)]
    )
    jsonschema.validate(json.loads(render_json(report)), schema)
    jsonschema.validate(
        {
            "schema_version": "3.0",
            "dockroute_version": "0.2.0",
            "error": {"code": "DOCKER_UNAVAILABLE", "message": "Unavailable"},
        },
        schema,
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**report, "env": {"PASSWORD": "leak"}}, schema)
