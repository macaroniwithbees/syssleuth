import psutil

RISKY_PORTS = {
    21: "FTP (unencrypted)",
    23: "Telnet (unencrypted)",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

def get_listening_ports():
    """Get a list of listening ports on the system."""
    results = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN:
            continue
        try:
            proc = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
        except  (psutil.NoSuchProcess, psutil.AccessDenied):
            proc = "Unknown"
        results.append({
            "port": conn.laddr.port,
            "address": conn.laddr.ip,
            "process": proc
        })
    return sorted(results, key=lambda x: x["port"])

def assess(entry):
    """Assess the risk of a given port entry."""
    exposed = entry["address"] in ("0.0.0.0", "::")
    
    if entry["port"] in RISKY_PORTS:
        note = RISKY_PORTS[entry["port"]]
        return ("HIGH", f"{note}, exposed to network") if exposed else ("MEDIUM", f"{note}, localhost only")
    if exposed:
        return ("LOW", "Listening on all interfaces")
    return ("OK", "Localhost only")