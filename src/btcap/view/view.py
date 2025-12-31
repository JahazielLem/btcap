from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

def PRINT_SUCCESS(msg):
  console.print(f"[*] {msg}", style="green")
def PRINT_WARNING(msg):
  console.print(f"[-] {msg}", style="yellow")
def PRINT_ERROR(msg):
  console.print(f"[X] {msg}", style="red")

def show_sessions(sessions):
  table = Table(title=f"Active Sessions: {len(sessions)}", box=box.MINIMAL, row_styles=["", "dim"])
  table.add_column("No.")
  table.add_column("Name")
  table.add_column("Alias")
  table.add_column("Connections")
  table.add_column("Path")
  for sid in sessions:
    session = sessions.get(sid)
    table.add_row(str(sid), str(session.name), str(session.alias if session.alias else ""), str(session.connection.get_connection_count()), str(session.path))
  console.print(table)

def show_session_summary(session):
  table = Table(title=f"Session: {session.alias if session.alias else session.name} Connections: {session.connection.get_connection_count()}", box=box.MINIMAL, row_styles=["", "dim"])
  table.add_column("No.")
  table.add_column("Access Address")
  table.add_column("Start Conn")
  table.add_column("Event Count")
  table.add_column("State")
  connections = session.connection.get_connections()
  for i, aa in enumerate(connections):
    conn = connections[aa]
    ended = "[yellow]Incomplete[/yellow]"
    if not conn.active:
      ended = "[green]Complete[/green]"
    table.add_row(str(i), str(hex(conn.aa)), str(conn.start_idx + 1), str(len(conn.events)), str(ended))
  console.print(table)