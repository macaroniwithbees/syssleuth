import os
from rich.console import Console
from rich.table import Table
from checks.ports import get_listening_ports, assess

COLORS = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "blue", "OK": "green"}
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "OK": 4}


def main():
    console = Console()

    if os.geteuid() != 0:
        console.print("[yellow]Not running as root: some process names will show as 'unknown'.[/]")

    table = Table(title="Listening Ports")
    for col in ("Proto", "Port", "Address", "Process", "Severity", "Note"):
        table.add_column(col)

    rows = []
    for entry in get_listening_ports():
        sev, note = assess(entry)
        rows.append((sev, entry, note))
    rows.sort(key=lambda r: ORDER[r[0]])

    for sev, entry, note in rows:
        table.add_row(
            entry["proto"], str(entry["port"]), entry["address"],
            entry["process"], f"[{COLORS[sev]}]{sev}[/]", note,
        )
    console.print(table)


if __name__ == "__main__":
    main()