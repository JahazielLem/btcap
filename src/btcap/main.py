#!/usr/bin/venv python
# Copyright 2025 - 2025, Kevin Leon
# SPDX-License-Identifier: GPL-3.0-only
import argparse
import cmd
from pathlib import Path
from cli.handler import Context, CLIState, CommandDispatcher
from cli.cli import Session, Show, Set

class BTCapShell(cmd.Cmd):
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
      self.prompt = f"btcap(session:{self.dispatcher.state.current_session.id}) > "
    elif ctx == Context.DEVICE:
      self.prompt = "btcap(device) > "
    return stop
  
  def do_help(self, arg):
    ctx = self.dispatcher.context()
    for cmd in self.dispatcher.commands.values():
      if ctx in cmd.contexts:
        print(f"{cmd.name:10} {cmd.help}")

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('filename', type=Path)
  args = parser.parse_args()
  state = CLIState(args.filename)
  dispatcher = CommandDispatcher(state)
  dispatcher.register(Session())
  dispatcher.register(Show())
  dispatcher.register(Set())

  BTCapShell(dispatcher).cmdloop()

