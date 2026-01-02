from core.state import Command, CommandGroup, Context
from view.view import PRINT_ERROR, PRINT_WARNING, PRINT_SUCCESS
from view.view import show_tree_connection, show_pcap_connection, show_summary_packets

# UNIQUE EVENT
class ShowHexdump(Command):
  name = "hex"
  help = "Show Hexdump format"
  usage = "show hex <id>"
  is_root = False
  contexts = {Context.SESSION}

  def run(self, args, state):
    if not args:
      PRINT_ERROR("Connection ID required")
      return
    try:
      sid = int(args[0])
    except ValueError:
        PRINT_ERROR("Invalid session id")

# SHOW ALL THE EVENTS INFORMATION

class ShowPcap(Command):
  name = "pcap"
  help = "Show PCAP format <id>"
  usage = "show pcap"
  is_root = False
  contexts = {Context.SESSION}

  def run(self, args, state):
    if state.current_session is None:
      PRINT_ERROR("Session id is required")
      return
    show_pcap_connection(state.current_session.connection)

class ShowTree(Command):
  name = "tree"
  help = "Show Tree format"
  usage = "show tree"
  is_root = False
  contexts = {Context.SESSION}

  def run(self, args, state):
    if state.current_session is None:
      PRINT_ERROR("Session id is required")
      return
    show_tree_connection(state.current_session.connection)

class ShowSummary(Command):
  name = "summary"
  help = "Show the summary of the connection"
  usage = "show summary"
  is_root = False
  contexts = {Context.SESSION}

  def run(self, args, state):
    if state.current_session is None:
      PRINT_ERROR("Session id is required")
      return
    show_summary_packets(state.current_session.connection)

class Show(CommandGroup):
  name = "show"
  help = "Show event information <id>"
  usage = "show <id>"
  aliases = []
  contexts = {Context.SESSION}
  
  def __init__(self):
    super().__init__()
    self.register(ShowTree())
    self.register(ShowHexdump())
    self.register(ShowSummary())
    self.register(ShowPcap())