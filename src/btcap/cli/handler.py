#!/usr/bin/venv python
# Copyright 2025 - 2025, Kevin Leon
# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
from enum import Enum, auto
from rich.console import Console
from cli.bt_sessions import BTContext, FMTPacket, BTFormatPrint

console = Console()
class Context(Enum):
  GLOBAL  = auto()
  SESSION = auto()
  DEVICE  = auto()

class CLIState:
  def __init__(self, path: Path):
    self.bt_context: BTContext = BTContext(path)
    self.sessions        = self.bt_context.get_sessions()
    self.current_session = None
    self.device          = None
    self.filters         = []
    self.view_mode       = FMTPacket.BRIEF
    console.print(BTFormatPrint().show_connections(self.sessions))

class Command:
  name = ""
  aliases = []
  contexts = {Context.GLOBAL}
  help = ""
  
  def run(self, args, state: CLIState):
    raise NotImplementedError

class CommandDispatcher:
  def __init__(self, state: CLIState):
    self.state = state
    self.commands = {}
    
  def register(self, cmd: Command):
    self.commands[cmd.name] = cmd
    for a in cmd.aliases:
      self.commands[a] = cmd
  
  def dispatch(self, line: str):
    if not line.strip():
      return
  
    parts = line.split()
    name = parts[0]
    args = parts[1:]
    
    cmd = self.commands.get(name)
    if not cmd:
      print(f"[X] Unknown command: {name}")
      return
    
    ctx = self.context()
    if ctx not in cmd.context:
      print(f"[X] Command '{name}' not available in {ctx.name} context")
      return
    
    cmd.run(args, self.state)
  
  def context(self):
    if self.state.device:
      return Context.DEVICE
    if self.state.current_session:
      return Context.SESSION
    return Context.GLOBAL