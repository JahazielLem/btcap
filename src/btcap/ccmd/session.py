from core.state import Command, CommandGroup, Context
from view.view import PRINT_ERROR, PRINT_WARNING, PRINT_SUCCESS
from view.view import show_session_summary, show_sessions, show_connection_summary

class SessionList(Command):
  name = "list"
  help = "List sessions"
  is_root = False
  contexts = {Context.GLOBAL, Context.SESSION}

  def run(self, args, state):
    show_sessions(state.sessions)

class SessionSet(Command):
  name = "set"
  help = "Select a session"
  usage = "session set <id>"
  is_root = False
  contexts = {Context.GLOBAL, Context.SESSION}

  def run(self, args, state):
    if not args:
      PRINT_ERROR("Session ID required")
      return
    try:
      sid = int(args[0])
      sess = state.get_session(sid)
      if not sess:
        PRINT_WARNING(f"Invalid session: {sid}")
        return
      PRINT_SUCCESS("Session set")
      state.set_session(sess)
    except ValueError:
        PRINT_ERROR("Invalid session id")

class SessionAlias(Command):
  name = "alias"
  help = "Select a session alias"
  usage = "session alias <alias>"
  is_root = False
  contexts = {Context.GLOBAL, Context.SESSION}

  def run(self, args, state):
    if not args:
      PRINT_ERROR("Session alias required")
      return
    try:
      PRINT_SUCCESS(f"Alias changed to: {args[0]}")
      state.current_session.set_alias(args[0])
    except ValueError:
        PRINT_ERROR("Invalid alias")

class SessionShow(Command):
  name = "show"
  help = "Show detailed info of the session"
  usage = "session show <session_id>"
  is_root = False
  contexts = {Context.GLOBAL, Context.SESSION}

  def run(self, args, state):
    if not args and state.current_session is None:
      PRINT_ERROR("Session id is required")
      return
    if not args and state.current_session:
      show_session_summary(state.current_session)
      return
    try:
      sid = int(args[0])
      sess = state.get_session(sid)
      if not sess:
        PRINT_WARNING(f"Invalid session: {sid}")
        return
      show_session_summary(sess)
    except ValueError:
        PRINT_ERROR("Invalid alias")


class ConnectionList(Command):
  name = "list"
  help = "List connections"
  is_root = False
  contexts = {Context.SESSION}

  def run(self, args, state):
    if state.current_session:
      show_session_summary(state.current_session)
    else:
      PRINT_WARNING("First select session")

class ConnectionShow(Command):
  name = "show"
  help = "Show detailed info of the connection"
  usage = "connection show <connection_id>"
  is_root = False
  contexts = {Context.GLOBAL, Context.SESSION}

  def run(self, args, state):
    if not args:
      PRINT_ERROR("Connection id is required")
      return
    try:
      sid = int(args[0])
    except ValueError:
        PRINT_ERROR("Invalid alias")

class Connection(CommandGroup):
  name = "connections"
  help = "Show connection or set connection using the <id>"
  usage = "connection <id>"
  aliases = ["con", "connection"]
  contexts = {Context.SESSION}
  
  def __init__(self):
    super().__init__()
    self.register(ConnectionShow())
    self.register(ConnectionList())

class Session(CommandGroup):
  name = "sessions"
  help = "Show sessions or set session using the <id>"
  usage = "sessions <id>"
  aliases = ["ss", "session"]
  contexts = {Context.GLOBAL, Context.SESSION}
  
  def __init__(self):
    super().__init__()
    self.register(SessionAlias())
    self.register(SessionSet())
    self.register(SessionShow())
    self.register(SessionList())