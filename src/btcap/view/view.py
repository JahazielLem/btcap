from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich import box
from bt.bt import BTEventType

console = Console()

def _fmt_event(ev):
  base = f"[{ev.idx}] {ev.type.name}"
  if ev.handle:
    base += f" handle={hex(ev.handle)}"
  if ev.value:
    base += f" value={ev.value.hex()} | value= {ev.value.decode('utf-8', errors='replace')}"
  return base


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

def show_connection_summary(connection):
  table = Table(title=f"Connection:", box=box.MINIMAL, row_styles=["", "dim"])
  table.add_column("No.")
  table.add_column("Access Address")
  table.add_column("Start Conn")
  table.add_column("Event Count")
  table.add_column("State")
  ended = "[yellow]Incomplete[/yellow]"
  if not connection.active:
    ended = "[green]Complete[/green]"
  table.add_row(str(connection.id), str(hex(connection.aa)), str(connection.start_idx + 1), str(len(connection.events)), str(ended))
  console.print(table)
  
def show_summary_packets(connection):
  table = Table(title=f"[bold]Summary Connection: {connection.id}[/bold]", box=box.MINIMAL, row_styles=["", "dim"])
  table.add_column("Packet No.")
  table.add_column("Event")
  table.add_column("Handle")
  table.add_column("Value")
  for ev in connection.events:
    if ev.type != BTEventType.GENERIC or ev.type != BTEventType.ADV:
      handle = ""
      if ev.handle:
        handle = str(hex(ev.handle))
      value = ""
      if ev.value:
        value = str(ev.value.hex())
      table.add_row(str(ev.idx), str(ev.type.name), handle, value)
    console.print(table)
  
def show_tree_connection(connection):
  root = Tree(f"Connection {connection.id}", highlight=Tree)
  for ev in connection.events:
    if ev.parent:
      continue
    node = root.add(_fmt_event(ev))
    for child in ev.children:
      node.add(_fmt_event(child))
  console.print(root)

def show_pcap_connection(connection):
  for ev in connection.raw_packets:
    console.print(ev.summary())