"""Self-contained Linux helper program; runs only inside an opt-in helper container.

This module also permits local socket/table tests without requiring Docker.
Never echo arguments, raw exceptions, DNS files or application logs.

Entry clocks begin after importing time, at the first measurable script statement.
They exclude interpreter startup (and package initialization when imported locally).
import_ms covers the remaining imports; ready_ms also includes argument parsing.
"""

# ruff: noqa: E402, I001 -- clock capture must precede all other imports.
import time

_SCRIPT_ENTRY_PERF = time.perf_counter()
_SCRIPT_ENTRY_WALL = time.time()

import errno
import json
import signal
import socket
import sys

_IMPORT_MS = (time.perf_counter() - _SCRIPT_ENTRY_PERF) * 1000


def inspect_listeners(port, proc_dir="/proc/net"):
    addresses = set()
    verified = True
    for filename, family in (("tcp", socket.AF_INET), ("tcp6", socket.AF_INET6)):
        try:
            with open(f"{proc_dir}/{filename}") as file:
                text = file.read(2 * 1024 * 1024 + 1)
            if len(text) > 2 * 1024 * 1024:
                return [], False
            for line in text.splitlines()[1:]:
                fields = line.split()
                if len(fields) < 4 or fields[3] != "0A":
                    continue
                address, port_hex = fields[1].split(":")
                if int(port_hex, 16) != port:
                    continue
                raw = b"".join(
                    int(address[i : i + 8], 16).to_bytes(4, sys.byteorder)
                    for i in range(0, len(address), 8)
                )
                addresses.add(socket.inet_ntop(family, raw))
        except (OSError, ValueError):
            verified = False
    return sorted(addresses), verified


def _ipv4_packed(address):
    octets = address.split(".")
    if len(octets) != 4 or any(
        not octet
        or not octet.isascii()
        or not octet.isdecimal()
        or len(octet) > 3
        or (len(octet) > 1 and octet[0] == "0")
        or int(octet) > 255
        for octet in octets
    ):
        raise ValueError("Invalid IP address")
    return bytes(int(octet) for octet in octets)


def _ip_key(value):
    # Preserve ip_address equivalence without importing its full address model.
    # Keep family and scope separate: mapped IPv6 is not IPv4, and scopes differ.
    if isinstance(value, int):
        if not 0 <= value < 2**128:
            raise ValueError("Invalid IP address")
        family, size = (socket.AF_INET, 4) if value < 2**32 else (socket.AF_INET6, 16)
        return family, value.to_bytes(size, "big"), ""
    if isinstance(value, bytes):
        if len(value) not in (4, 16):
            raise ValueError("Invalid IP address")
        return (socket.AF_INET if len(value) == 4 else socket.AF_INET6), value, ""
    address = str(value)
    if "/" in address:
        raise ValueError("Invalid IP address")
    if ":" not in address:
        return socket.AF_INET, _ipv4_packed(address), ""
    address, separator, scope = address.partition("%")
    if separator and (not scope or "%" in scope):
        raise ValueError("Invalid IP address")
    if "." in address:
        _ipv4_packed(address.rsplit(":", 1)[-1])
    try:
        return socket.AF_INET6, socket.inet_pton(socket.AF_INET6, address), scope
    except OSError:
        raise ValueError("Invalid IP address") from None


def _arm_deadline(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    signal.setitimer(signal.ITIMER_REAL, remaining)


def _decode_dns_response(data, port):
    invalid = "Invalid private resolver response"
    if len(data) > 65536:
        raise ValueError(invalid)
    try:
        message = json.loads(data)
    except (ValueError, UnicodeError):
        raise ValueError(invalid) from None
    if not isinstance(message, dict):
        raise ValueError(invalid)
    if message.get("status") == "gaierror":
        if set(message) != {"status", "category"} or message["category"] not in (
            "EAI_AGAIN",
            "EAI_NONAME",
            "OTHER",
        ):
            raise ValueError(invalid)
        code = getattr(socket, message["category"], socket.EAI_FAIL)
        raise socket.gaierror(code, "Resolver lookup failed")
    if message.get("status") == "error":
        if set(message) != {"status", "category"}:
            raise ValueError(invalid)
        if message["category"] == "TimeoutError":
            raise TimeoutError()
        if message["category"] == "OSError":
            raise OSError("Resolver execution failed")
        if message["category"] == "ValueError":
            raise ValueError("Resolver execution failed")
        raise ValueError(invalid)
    if set(message) != {"status", "records"} or message["status"] != "ok":
        raise ValueError(invalid)
    records = message["records"]
    if not isinstance(records, list) or len(records) > 64:
        raise ValueError(invalid)
    restored = []
    for record in records:
        if not isinstance(record, list) or len(record) != 4:
            raise ValueError(invalid)
        family, kind, protocol, address = record
        if (
            type(family) is not int
            or family not in (socket.AF_INET, socket.AF_INET6)
            or type(kind) is not int
            or kind != socket.SOCK_STREAM
            or type(protocol) is not int
            or protocol not in (0, socket.IPPROTO_TCP)
            or not isinstance(address, list)
            or len(address) != (2 if family == socket.AF_INET else 4)
            or not isinstance(address[0], str)
            or len(address[0]) > 256
            or type(address[1]) is not int
            or address[1] != port
            or any(type(value) is not int or not 0 <= value < 2**32 for value in address[2:])
        ):
            raise ValueError(invalid)
        if _ip_key(address[0])[0] != family:
            raise ValueError(invalid)
        restored.append((family, kind, protocol, "", tuple(address)))
    return restored


def _read_dns_response(descriptor, deadline, os_api, selector, port):
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        try:
            ready, _, _ = selector.select([descriptor], [], [], remaining)
            if not ready:
                raise TimeoutError()
            chunk = os_api.read(descriptor, min(4096, 65537 - len(data)))
        except InterruptedError:
            continue
        if not chunk:
            return _decode_dns_response(data, port)
        data.extend(chunk)
        if len(data) > 65536:
            raise ValueError("Private resolver response exceeds the limit")


def _resolve_in_child(host, port, deadline):
    # libc resolvers can defer Python signal handlers. Isolate one lookup so the
    # parent can enforce its deadline while the child is blocked in C.
    import os
    import select

    blocked_signals = {signal.SIGALRM, signal.SIGINT}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
    read_fd, write_fd, child = None, None, None
    try:
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            # SIGALRM/SIGINT stay blocked in this child; only its parent owns the
            # deadline/cancellation. SIGKILL always terminates a blocked resolver.
            try:
                os.close(read_fd)
                try:
                    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                    if len(records) > 64:
                        raise ValueError("Resolver record limit exceeded")
                    message = {
                        "status": "ok",
                        "records": [
                            [family, kind, proto, address]
                            for family, kind, proto, _, address in records
                        ],
                    }
                except socket.gaierror as exc:
                    category = (
                        "EAI_AGAIN"
                        if exc.errno == socket.EAI_AGAIN
                        else "EAI_NONAME"
                        if exc.errno == socket.EAI_NONAME
                        else "OTHER"
                    )
                    message = {"status": "gaierror", "category": category}
                except BaseException as exc:
                    message = {
                        "status": "error",
                        "category": "TimeoutError"
                        if isinstance(exc, TimeoutError)
                        else "OSError"
                        if isinstance(exc, OSError)
                        else "ValueError",
                    }
                encoded = json.dumps(message, separators=(",", ":")).encode()
                if len(encoded) > 65536:
                    encoded = b'{"status":"error","category":"ValueError"}'
                offset = 0
                while offset < len(encoded):
                    offset += os.write(write_fd, encoded[offset:])
            except BaseException:
                # A pipe error must not print a traceback or a second wire frame.
                pass
            finally:
                try:
                    os.close(write_fd)
                except OSError:
                    pass
                os._exit(0)
        os.close(write_fd)
        write_fd = None
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        return _read_dns_response(read_fd, deadline, os, select, port)
    finally:
        # Defer timeout/cancellation until the owned child is reaped and both
        # descriptors are closed; this also protects fork/PID-assignment races.
        signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
        try:
            if child:
                try:
                    waited, _ = os.waitpid(child, os.WNOHANG)
                except ChildProcessError:
                    waited = child
                if not waited:
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    while True:
                        try:
                            os.waitpid(child, 0)
                            break
                        except InterruptedError:
                            continue
                        except ChildProcessError:
                            break
        finally:
            try:
                for descriptor in (read_fd, write_fd):
                    if descriptor is not None:
                        os.close(descriptor)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def tcp_check(
    host,
    port,
    timeout,
    allowed_ips=None,
    observations=None,
    *,
    dns_timeout=None,
    connect_timeout=None,
):
    result = (
        observations
        if observations is not None
        else {"dns": "unknown", "tcp": "unknown", "addresses": []}
    )
    deadline = min(time.monotonic() + timeout, result.get("_execution_deadline", float("inf")))
    dns_deadline = min(
        deadline, time.monotonic() + dns_timeout if dns_timeout is not None else deadline
    )
    watchdog = result.get("_watchdog", False)
    result["_phase"] = "dns"
    dns_started = time.perf_counter()
    try:
        if watchdog:
            _arm_deadline(dns_deadline)
        records = (
            _resolve_in_child(host, port, dns_deadline)
            if watchdog
            else socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )
        if time.monotonic() >= dns_deadline:
            raise TimeoutError()
    except socket.gaierror:
        # A temporary resolver error is still lookup-failure evidence, not NXDOMAIN
        # or a claimed expired deadline. Only elapsed deadlines are timeouts.
        if time.monotonic() >= dns_deadline:
            result.update(dns="timeout", timeout_stage="dns")
        else:
            result["dns"] = "failed"
        return result
    except TimeoutError:
        result.update(dns="timeout", timeout_stage="dns")
        return result
    finally:
        result["dns_ms"] = (time.perf_counter() - dns_started) * 1000
        if watchdog:
            _arm_deadline(deadline)
    result["dns"] = "ok"
    result["_phase"] = "tcp"
    tcp_started = time.perf_counter()
    try:
        result["addresses"] = sorted({r[4][0] for r in records})
        permitted = None if allowed_ips is None else {_ip_key(x) for x in allowed_ips}
        outcomes = []
        visited = set()
        for family, socktype, protocol, _, sockaddr in records:
            ip = _ip_key(sockaddr[0])
            if permitted is not None and ip not in permitted:
                continue
            if ip in visited:
                continue
            visited.add(ip)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcomes.append("timeout")
                break
            try:
                with socket.socket(family, socktype, protocol) as s:
                    s.settimeout(
                        min(remaining, connect_timeout)
                        if connect_timeout is not None
                        else remaining
                    )
                    s.connect(sockaddr)
                result["tcp"] = "ok"
                return result
            except ConnectionRefusedError:
                outcomes.append("refused")
            except (TimeoutError, socket.timeout):
                outcomes.append("timeout")
            except OSError as exc:
                outcomes.append("refused" if exc.errno == errno.ECONNREFUSED else "unknown")
        if outcomes and all(x == "refused" for x in outcomes):
            result["tcp"] = "refused"
        elif "timeout" in outcomes:
            result["tcp"] = "timeout"
            result["timeout_stage"] = "tcp"
        elif not visited:
            result["tcp"] = "blocked"
        return result
    finally:
        result["tcp_ms"] = (time.perf_counter() - tcp_started) * 1000


def run(payload, resolver_dir="/etc", observations=None):
    if payload["mode"] == "listen":
        addresses, verified = inspect_listeners(payload["port"])
        return {
            "listener_addresses": addresses,
            "listener_verified": verified,
            "state": "SUCCESS" if verified else "UNKNOWN",
        }
    matched = None
    files = payload.get("dns_files", {})
    if set(files) == {"resolv.conf", "hosts"}:
        try:
            actual = {}
            for name in files:
                with open(f"{resolver_dir}/{name}", encoding="utf-8", newline="") as file:
                    actual[name] = file.read(65537)
            matched = actual == files
        except (OSError, UnicodeError):
            pass
    if observations is not None:
        observations["dns_equivalent"] = matched
    arguments = (payload["host"], payload["port"], payload["timeout"], payload.get("allowed_ips"))
    options = {key: payload[key] for key in ("dns_timeout", "connect_timeout") if key in payload}
    if observations is not None:
        options["observations"] = observations
    result = tcp_check(*arguments, **options) if options else tcp_check(*arguments)
    # Namespace-sharing containers may share donor resolver mounts. Never write them.
    result["dns_equivalent"] = matched
    result["state"] = (
        "SUCCESS"
        if result.get("tcp") == "ok"
        else "DNS_FAILURE"
        if result.get("dns") in {"failed", "timeout"}
        else "TCP_REFUSED"
        if result.get("tcp") == "refused"
        else "TCP_TIMEOUT"
        if result.get("tcp") == "timeout"
        else "UNKNOWN"
    )
    result.pop("_phase", None)
    result.pop("_execution_deadline", None)
    result.pop("_watchdog", None)
    return result


def main():
    def expired(signum, frame):
        raise TimeoutError()

    payload = json.loads(sys.argv[1])
    payload.setdefault("dns_timeout", 2.0)
    payload.setdefault("connect_timeout", 1.0)
    print(
        json.dumps(
            {
                "event": "ready",
                "worker_schema": "2",
                "import_ms": _IMPORT_MS,
                "ready_ms": (time.perf_counter() - _SCRIPT_ENTRY_PERF) * 1000,
                "wall_ts": time.time(),
            }
        ),
        flush=True,
    )
    execution_started = time.perf_counter()
    execution_deadline = time.monotonic() + payload["timeout"]
    partial: dict = {
        "dns": "unknown",
        "tcp": "unknown",
        "addresses": [],
        "dns_equivalent": None,
        "listener_addresses": [],
        "listener_verified": False,
        "_phase": "execution",
        "_execution_deadline": execution_deadline,
        "_watchdog": True,
    }
    signal.signal(signal.SIGALRM, expired)
    try:
        _arm_deadline(execution_deadline)
        result = run(payload, observations=partial)
    except TimeoutError:
        result = {**partial, "state": "HELPER_TIMEOUT", "timeout_stage": partial["_phase"]}
        if partial["_phase"] == "dns":
            result.update(state="DNS_FAILURE", dns="timeout")
        elif partial["_phase"] == "tcp":
            result.update(state="TCP_TIMEOUT", tcp="timeout")
    except (OSError, ValueError) as exc:
        result = {
            **partial,
            "state": "HELPER_EXECUTION_FAILED",
            "error_type": "OSError" if isinstance(exc, OSError) else "ValueError",
        }
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    result.pop("_phase", None)
    result.pop("_execution_deadline", None)
    result.pop("_watchdog", None)
    result["execution_ms"] = (time.perf_counter() - execution_started) * 1000
    print(json.dumps({"event": "result", "worker_schema": "2", **result}), flush=True)


if __name__ == "__main__":
    main()
