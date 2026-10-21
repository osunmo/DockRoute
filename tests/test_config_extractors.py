"""Mounted configuration evidence must be useful, bounded and secret-safe."""

import io
import tarfile

import pytest

from dockroute.config_extractors import (
    MAX_ARCHIVE_BYTES,
    MAX_FILE_BYTES,
    ConfigDocument,
    collect_mounted_configs,
    extract_configs,
)


def document(kind, content, path="/config/test.conf"):
    return ConfigDocument(kind, path, content.encode())


def endpoints(result):
    return {(hint.host, hint.port) for hint in result.hints}


def test_nginx_resolves_referenced_upstreams_across_documents_and_omits_listeners():
    result = extract_configs(
        [
            document(
                "nginx",
                "upstream app { server web:8000; server backup:8001 backup; server dead:80 down; } upstream unused { server unused:90; }",
            ),
            document(
                "nginx",
                "server { listen 8000; server_name public.example; location / { proxy_pass http://app/private; } }",
            ),
        ]
    )
    assert endpoints(result) == {("web", 8000), ("backup", 8001)}
    assert all(hint.evidence.kind == "mounted_config" for hint in result.hints)


def test_nginx_literal_grpc_ipv6_comments_quotes_and_credentials_are_safe():
    result = extract_configs(
        [
            document(
                "nginx",
                """
    # proxy_pass http://comment:90;
    server { location / { proxy_pass "https://user:TOPSECRET@web/path?token=SECRET"; }
    location /grpc { grpc_pass grpc://rpc:50051; }
    location /ipv6 { proxy_pass http://[::1]:8000; } }
    """,
            )
        ]
    )
    assert endpoints(result) == {("web", 443), ("rpc", 50051), ("::1", 8000)}
    assert "TOPSECRET" not in repr(result)
    assert "token" not in repr(result)
    assert "TOPSECRET" not in repr(document("nginx", "TOPSECRET"))


def test_nginx_variables_includes_unix_sockets_and_srv_do_not_invent_targets():
    result = extract_configs(
        [
            document(
                "nginx",
                """
    include /secrets/anything.conf;
    upstream service { server foo service=http resolve; server unix:/socket; }
    server { proxy_pass http://service; location / { proxy_pass http://$upstream; } }
    """,
            )
        ]
    )
    assert not result.hints
    assert "CONFIG_INCLUDES_NOT_FOLLOWED" in result.issues
    assert "CONFIG_UNRESOLVED_VARIABLE" in result.issues
    assert "CONFIG_UNSUPPORTED_ENDPOINT" in result.issues
    assert "secrets" not in repr(result)


def test_nginx_bare_group_server_uses_documented_default_port():
    result = extract_configs(
        [
            document(
                "nginx", "upstream backend { server web; } server { proxy_pass http://backend; }"
            )
        ]
    )
    assert endpoints(result) == {("web", 80)}


def test_duplicate_nginx_group_abstains_instead_of_treating_name_as_dns():
    result = extract_configs(
        [
            document(
                "nginx",
                "upstream a { server one:80; } upstream a { server two:80; } server { proxy_pass http://a; }",
            )
        ]
    )
    assert not result.hints
    assert "CONFIG_AMBIGUOUS_UPSTREAM" in result.issues


def test_prometheus_extracts_static_targets_only():
    result = extract_configs(
        [
            document(
                "prometheus",
                """
    external_url: http://public:90
    scrape_configs:
      - job_name: ignored-secret-name
        scheme: https
        static_configs:
          - targets: ["exporter:9100", "other", "[::1]:9090"]
        relabel_configs:
          - target_label: unrelated
            regex: "fake:99"
        file_sd_configs:
          - files: ["/secret.json"]
    """,
            )
        ]
    )
    assert endpoints(result) == {("exporter", 9100), ("other", 443), ("::1", 9090)}
    assert "CONFIG_DYNAMIC_DISCOVERY_NOT_READ" in result.issues
    assert "ignored-secret-name" not in repr(result)


def test_prometheus_address_relabeling_is_ambiguous_not_a_confirmed_static_target():
    result = extract_configs(
        [
            document(
                "prometheus",
                """
    scrape_configs:
      - static_configs: [{targets: ["original:80"]}]
        relabel_configs:
          - target_label: __address__
            replacement: replacement:90
    """,
            )
        ]
    )
    assert not result.hints
    assert "CONFIG_TARGET_RELABELING_UNSUPPORTED" in result.issues


def test_envoy_only_static_cluster_tcp_endpoint_addresses():
    result = extract_configs(
        [
            document(
                "envoy",
                """
    admin: {address: {socket_address: {address: 127.0.0.1, port_value: 9901}}}
    static_resources:
      listeners: [{address: {socket_address: {address: 0.0.0.0, port_value: 80}}}]
      clusters:
        - name: backend
          load_assignment:
            endpoints:
              - lb_endpoints:
                  - endpoint: {address: {socket_address: {address: api, port_value: 8000}}}
                  - endpoint: {address: {socket_address: {address: udp, port_value: 99, protocol: UDP}}}
                  - endpoint: {address: {socket_address: {address: named, named_port: http}}}
    dynamic_resources: {cds_config: {path: /secrets/remote.yml}}
    """,
            )
        ]
    )
    assert endpoints(result) == {("api", 8000)}
    assert "CONFIG_DYNAMIC_DISCOVERY_NOT_READ" in result.issues
    assert "CONFIG_UNSUPPORTED_ENDPOINT" in result.issues


@pytest.mark.parametrize(
    "kind,content",
    [
        ("prometheus", "scrape_configs: [{scheme: []}]"),
        ("prometheus", "scrape_configs: [{relabel_configs: [{target_label: []}]}]"),
        ("prometheus", "scrape_configs: [{relabel_configs: [{action: {}}]}]"),
        ("envoy", "static_resources: {clusters: [{type: []}]}"),
        (
            "envoy",
            "static_resources: {clusters: [{load_assignment: {endpoints: [{lb_endpoints: [{endpoint: {address: {socket_address: {address: api, port_value: 80, protocol: []}}}}]}]}}]}",
        ),
    ],
)
def test_malformed_schema_types_return_safe_issues_instead_of_crashing(kind, content):
    result = extract_configs([document(kind, content)])
    assert not result.hints
    assert result.issues


def test_prometheus_targets_must_be_host_port_not_urls_with_credentials_or_paths():
    result = extract_configs(
        [
            document(
                "prometheus",
                """
    scrape_configs:
      - static_configs:
          - targets: ["https://secret:password@web:80/path", "web:80/path", "user:password@web:80", "good:80"]
    """,
            )
        ]
    )
    assert endpoints(result) == {("good", 80)}
    assert "password" not in repr(result)


def test_tar_root_symlink_report_prevents_stream_consumption():
    calls = []

    def get_archive(path):
        def stream():
            calls.append(True)
            yield b"should never read"

        return stream(), {"linkTarget": "/etc/shadow"}

    result = collect_mounted_configs(
        [{"Type": "bind", "Destination": "/etc/nginx/nginx.conf"}], get_archive
    )
    assert not calls
    assert not result.documents
    assert result.issues == ("CONFIG_ARCHIVE_UNSAFE_MEMBER",)


@pytest.mark.parametrize(
    "content",
    ["a: &a [*a]", "a: 1\na: 2", "!!python/object/apply:os.system ['bad']", "[" * 40 + "]" * 40],
)
def test_untrusted_yaml_rejected_without_exposing_content(content):
    result = extract_configs([document("envoy", content)])
    assert not result.hints
    assert result.issues
    assert content not in repr(result)


@pytest.mark.parametrize(
    "content",
    [b"x" * (MAX_FILE_BYTES + 1), b"\xff", b"\x00bad"],
    ids=["oversize", "encoding", "nul"],
)
def test_file_size_encoding_and_nul_are_bounded(content):
    result = extract_configs([ConfigDocument("nginx", "/etc/nginx/nginx.conf", content)])
    assert not result.hints
    assert result.issues


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        for name, body, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(body) if kind == tarfile.REGTYPE else 0
            info.linkname = "/etc/shadow" if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE} else ""
            tar.addfile(info, io.BytesIO(body) if info.isreg() else None)
    return stream.getvalue()


def test_archive_reads_only_conventional_mount_destinations_not_host_sources():
    calls = []
    payload = archive(
        [("default.conf", b"server { proxy_pass http://api:8000; }", tarfile.REGTYPE)]
    )

    def get_archive(path):
        calls.append(path)
        return iter([payload]), {}

    result = collect_mounted_configs(
        [
            {
                "Type": "bind",
                "Source": "C:/private",
                "Destination": "/etc/nginx/conf.d/default.conf",
            },
            {"Type": "bind", "Destination": "/etc"},
            {"Type": "bind", "Destination": "/"},
            {"Type": "bind", "Destination": "/run/secrets/nginx.conf"},
            {"Type": "bind", "Destination": "/var/run/docker.sock"},
        ],
        get_archive,
    )
    assert calls == ["/etc/nginx/conf.d/default.conf"]
    assert endpoints(extract_configs(result.documents)) == {("api", 8000)}
    assert "C:/private" not in repr(result)


def test_exact_recognized_file_mount_at_custom_app_path_is_supported():
    calls = []

    def get_archive(path):
        calls.append(path)
        return iter([archive([("envoy.yaml", b"static_resources: {}", tarfile.REGTYPE)])]), {}

    result = collect_mounted_configs(
        [{"Type": "bind", "Destination": "/home/envoy/envoy.yaml"}], get_archive
    )
    assert calls == ["/home/envoy/envoy.yaml"]
    assert len(result.documents) == 1
    assert result.documents[0].kind == "envoy"


def test_directory_archive_filters_extensions_and_never_follows_links():
    payload = archive(
        [
            ("conf.d", b"", tarfile.DIRTYPE),
            ("conf.d/default.conf", b"server { proxy_pass http://api:8000; }", tarfile.REGTYPE),
            ("conf.d/token.txt", b"SECRET", tarfile.REGTYPE),
            ("conf.d/link.conf", b"", tarfile.SYMTYPE),
        ]
    )
    result = collect_mounted_configs(
        [{"Type": "volume", "Destination": "/etc/nginx/conf.d"}], lambda path: (iter([payload]), {})
    )
    assert len(result.documents) == 1
    assert "CONFIG_ARCHIVE_UNSAFE_MEMBER" in result.issues
    assert "SECRET" not in repr(result)


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../escape.conf", tarfile.REGTYPE),
        ("/etc/nginx.conf", tarfile.REGTYPE),
        ("nginx.conf", tarfile.LNKTYPE),
        ("nginx.conf", tarfile.FIFOTYPE),
    ],
)
def test_archive_traversal_links_and_special_files_rejected(name, kind):
    payload = archive([(name, b"server { proxy_pass http://api:8000; }", kind)])
    result = collect_mounted_configs(
        [{"Type": "bind", "Destination": "/etc/nginx/nginx.conf"}],
        lambda path: (iter([payload]), {}),
    )
    assert not result.documents
    assert "CONFIG_ARCHIVE_UNSAFE_MEMBER" in result.issues


def test_archive_stream_closed_on_size_limit_or_error_and_error_text_is_omitted():
    closed = []

    def chunks():
        try:
            yield b"x" * (MAX_ARCHIVE_BYTES + 1)
            raise AssertionError("must stop after cap")
        finally:
            closed.append(True)

    result = collect_mounted_configs(
        [{"Type": "bind", "Destination": "/etc/nginx/nginx.conf"}], lambda path: (chunks(), {})
    )
    assert not result.documents
    assert "CONFIG_ARCHIVE_SIZE_LIMIT" in result.issues
    assert closed == [True]

    def failing(path):
        raise RuntimeError("password=SECRET")

    result = collect_mounted_configs(
        [{"Type": "bind", "Destination": "/etc/nginx/nginx.conf"}], failing
    )
    assert result.issues == ("CONFIG_READ_FAILED",)
    assert "SECRET" not in repr(result)
