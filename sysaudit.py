from rich.console import Console
from rich.table import Table
from checks.ports import get_listening_ports, assess

COLORS = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "OK": "green"}

def main():
    console = Console()
    table = Table(title="Listening Ports")
    for col in ("Port", "Address", "Process", "Severity", "Note"):
        table.add_column(col)

    for entry in get_listening_ports():
        sev, note = assess(entry)
        table.add_row(str(entry["port"]), entry["address"], entry["process"],
                      f"[{COLORS[sev]}]{sev}[/]", note)
    console.print(table)

if __name__ == "__main__":
    main()