"""SDK-independent inspection, inference and diagnostic data contracts."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockroute.config_extractors import ConfigHint
    from dockroute.log_evidence import LogHint


@dataclass(frozen=True)
class Network:
    name: str
    id: str
    aliases: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class Port:
    container: int
    protocol: str = "tcp"
    host: int | None = None
    host_ip: str = ""


@dataclass(frozen=True)
class Container:
    id: str
    name: str
    project: str
    service: str
    state: str = "unknown"
    health: str = "none"
    restart_count: int = 0
    networks: dict[str, Network] = field(default_factory=dict)
    ports: tuple[Port, ...] = ()
    env: dict[str, str] = field(default_factory=dict, repr=False)
    healthcheck: tuple[str, ...] = field(default=(), repr=False)
    depends_on: tuple[str, ...] = ()
    working_dir: str = ""
    config_files: tuple[str, ...] = ()
    network_mode: str = ""
    extra_hosts: tuple[str, ...] = ()
    started_at: str = ""
    tty: bool = False
    mounts: tuple[dict, ...] = field(default=(), repr=False)
    config_hints: tuple["ConfigHint", ...] = field(default=(), repr=False)
    log_hints: tuple["LogHint", ...] = field(default=(), repr=False)
    supplemental_issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    kind: str
    detail: str


@dataclass(frozen=True)
class Connection:
    source_id: str
    source: str
    host: str
    port: int | None
    evidence: tuple[Evidence, ...] = ()
    explicit: bool = False


@dataclass(frozen=True)
class ProbeTrace:
    role: str
    stage: str
    state: str
    elapsed_ms: float
    error_type: str | None = None
    exit_code: int | None = None
    stderr: str = ""
    timeout_kind: str | None = None
    cleanup: str | None = None
    recovered: bool = False
    helper_configuration: dict | None = None
    timings: dict | None = None
    observe_mode: str | None = None


@dataclass(frozen=True)
class ProbeResult:
    dns: str = "unknown"
    tcp: str = "unknown"
    addresses: tuple[str, ...] = ()
    dns_equivalent: bool | None = None
    listener_addresses: tuple[str, ...] = ()
    listener_verified: bool = False
    notes: tuple[str, ...] = ()
    state: str = "UNKNOWN"
    listener_state: str = "UNKNOWN"
    failure_stage: str | None = None
    trace: tuple[ProbeTrace, ...] = ()
    execution_id: str | None = None
    startup_timeout: float = 15.0
    execution_timeout: float = 5.0
    listener_skipped: bool = False
    listener_skip_reason: str | None = None
    dns_timeout: float = 2.0
    connect_timeout: float = 1.0


@dataclass(frozen=True)
class Finding:
    code: str
    source: str
    source_container: str
    destination: str
    destination_service: str | None
    port: int | None
    observations: tuple[Evidence, ...]
    intention_evidence: tuple[Evidence, ...]
    explanation: str
    confidence: str
    remediation: str
    verification: str
    status: str = "UNKNOWN"
    probe: ProbeResult | None = None
