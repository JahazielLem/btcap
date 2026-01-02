import cmd
from enum import Enum, auto
from view.view import PRINT_ERROR, PRINT_WARNING

class Context(Enum):
  GLOBAL = auto()
  SESSION = auto()
  CONNECTION = auto()
  
class AppState:
  def __init__(self):
    self.context = Context.GLOBAL
    self.sessions = {}
    self.session_count = 0
    self.current_session = None
    self.current_connection = None
  
  def add_session(self, session) -> None: 
    session._set_id(self.session_count)
    self.sessions[self.session_count] = session
    self.session_count += 1

  def set_session(self, session):
    self.current_session = session
    self.context = Context.SESSION

  def set_connection(self, connection):
    self.current_connection = connection
    self.context = Context.CONNECTION
  
  def get_session(self, sid):
    return self.sessions.get(sid)

  def reset(self):
    self.current_session = None
    self.current_connection = None
    self.context = Context.GLOBAL


class Command:
  name = ""
  help = ""
  usage = ""
  aliases = []
  contexts = {}
  is_root = True

  def run(self, args, state):
    raise NotImplementedError

  def complete(self, args, state):
    return []

class CommandGroup(Command):
  def __init__(self):
    self.subcommands = {}
  
  def register(self, cmd: Command):
    self.subcommands[cmd.name] = cmd
  
  def run(self, args, state):
    if not args:
      self.show_help()
      return
    sub = args[0]
    
    subCmd = self.subcommands.get(sub)
    if not subCmd:
      PRINT_ERROR(f"Unknown subcommand: {sub}")
      return
    
    subCmd.run(args[1:], state)
  
  def complete(self, args, state):
    if len(args) <= 1:
      return list(self.subcommands.keys())
    sub = args[0]
    if sub in self.subcommands:
      return self.subcommands[sub].complete(args[1:], state)
    return []

  def show_help(self):
    for name, cmd in self.subcommands.items():
      usage = ""
      if cmd.usage:
        usage = f"\n\t{cmd.usage}"
      print(f"{cmd.name:10} {cmd.help}{usage}")
      

class CommandDispatcher:
  def __init__(self, state: AppState):
    self.state = state
    self.commands = {}
    
  def register(self, cmd: Command) -> None:
    self.commands[cmd.name] = cmd
    for a in cmd.aliases:
      self.commands[a] = cmd
  
  def dispatch(self, line: str) -> None:
    if not line.strip():
      return
  
    parts = line.split()
    name = parts[0]
    args = parts[1:]
    
    cmd = self.commands[name]
    if not cmd:
      print(f"[X] Unknown command: {name}")
      return
    
    ctx = self.context()
    if ctx not in cmd.contexts:
      print(f"[X] Command '{name}' not available in {ctx.name} context")
      return
    
    cmd.run(args, self.state)
  
  def context(self) -> Context:
    return self.state.context
  
  def root_commands(self):
    seen = set()
    roots = []
    for cmd in self.commands.values():
      if not cmd.is_root:
        continue
      if id(cmd) in seen:
        continue
      seen.add(id(cmd))
      roots.append(cmd)
    return roots

class ShellHandler(cmd.Cmd):
  intro = "BTCap console — type 'help' to list commands"
  prompt = "btcap > "

  def __init__(self, dispatcher):
    super().__init__()
    self.dispatcher = dispatcher

  def default(self, line):
    try:
      self.dispatcher.dispatch(line)
    except Exception as e:
      print(f"[!] Error: {e}")

  def do_exit(self, _):
    return True

  def do_EOF(self, _):
    return True
  
  def postcmd(self, stop, line):
    ctx = self.dispatcher.context()
    if ctx == Context.GLOBAL:
      self.prompt = "btcap > "
    elif ctx == Context.SESSION:
      session_name = self.dispatcher.state.current_session.alias if self.dispatcher.state.current_session.alias else self.dispatcher.state.current_session.name[:-5]
      session_fmt = f"{self.dispatcher.state.current_session.id} | {session_name}"
      self.prompt = f"btcap(session:{session_fmt}) > "
    elif ctx == Context.CONNECTION:
      self.prompt = f"btcap(session:{self.dispatcher.state.current_session.id}) Connection: > "
    return stop
  
  def do_help(self, arg):
    ctx = self.dispatcher.context()
    if arg:
      cmd = self.dispatcher.commands.get(arg)
      if not cmd:
        PRINT_ERROR(f"Unknown command: {arg}")
        return

      if isinstance(cmd, CommandGroup):
        cmd.show_help()
      else:
        print(f"{cmd.name}: {cmd.help}")
        if cmd.usage:
          print(f"Usage: {cmd.usage}")
      return

    for cmd in self.dispatcher.root_commands():
      if ctx in cmd.contexts:
        usage = ""
        if cmd.usage:
          usage = f"\n\t{cmd.usage}"
        print(f"{cmd.name:10} {cmd.help}{usage}")