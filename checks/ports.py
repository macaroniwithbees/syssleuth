import ipaddress
import socket
import psutil

RISKY_PORTS = {
    21: "FTP (unencrypted)",
    23: "Telnet (unencrypted)",
    3306: "MySQL",
    5432: "PostgreSQL",
    5355: "LLMNR (spoofable on untrusted networks)",
    6379: "Redis",
    27017: "MongoDB",
}


def classify_address(addr):
    """Bucket a bind address by who can reach it."""
    ip = ipaddress.ip_address(addr)
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "all"
    if ip.is_multicast:
        return "multicast"
    return "interface"


def get_process_name(pid):
    if not pid:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"


def get_listening_ports():
    """Return deduplicated TCP listeners and bound UDP sockets."""
    seen = set()
    results = []

    for conn in psutil.net_connections(kind="inet"):
        if not conn.laddr:
            continue

        if conn.type == socket.SOCK_STREAM:
            if conn.status != psutil.CONN_LISTEN:
                continue
            proto = "tcp"
        elif conn.type == socket.SOCK_DGRAM:
            if conn.raddr:
                continue
            proto = "udp"
        else:
            continue

        entry = {
            "proto": proto,
            "port": conn.laddr.port,
            "address": conn.laddr.ip,
            "scope": classify_address(conn.laddr.ip),
            "process": get_process_name(conn.pid),
        }

        if entry["scope"] == "all":
            key = (entry["proto"], entry["port"], entry["process"], "all")
        else:
            key = (entry["proto"], entry["port"], entry["process"], entry["address"])

        if key in seen:
            continue
        seen.add(key)
        results.append(entry)

    return sorted(results, key=lambda r: (r["proto"], r["port"]))


def assess(entry):
    """Return (severity, note) for a listening port."""
    scope = entry["scope"]
    port = entry["port"]

    if scope == "multicast":
        return ("INFO", "Multicast group membership")

    if scope == "loopback":
        if port in RISKY_PORTS:
            return ("LOW", f"{RISKY_PORTS[port]}, localhost only")
        return ("OK", "Localhost only")

    reach = "all interfaces" if scope == "all" else "LAN interface"
    if port in RISKY_PORTS:
        return ("HIGH", f"{RISKY_PORTS[port]}, exposed on {reach}")
    if scope == "all":
        return ("MEDIUM", "Listening on all interfaces")
    return ("LOW", "Reachable from local network")