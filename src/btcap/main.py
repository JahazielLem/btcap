#!/usr/bin/venv python
# Copyright 2025 - 2025, Kevin Leon
# SPDX-License-Identifier: GPL-3.0-only

"""TODO: Add session naming and descrption """

import argparse
from pathlib import Path
from core.state import AppState, CommandDispatcher, ShellHandler
from core.fsession import FSession
from ccmd.session import Session, Connection
from ccmd.show import Show

from view.view import show_sessions

if __name__ == "__main__":
  parser = argparse.ArgumentParser(prog="BTCap", description="BTCap - Bluetooth PCAP Connection analysis tool.", epilog="For more information check -> https://github.com/JahazielLem/btcap")
  parser.add_argument("-f", "--file", dest="filename", type=Path, help="PCAP/PCAPNG file to load")
  args = parser.parse_args()
  
  state = AppState()  
  
  if args.filename:
    session = FSession(args.filename)
    state.add_session(session=session)
  
  dispatcher = CommandDispatcher(state)
  show_sessions(state.sessions)
  dispatcher.register(Session())
  dispatcher.register(Connection())
  dispatcher.register(Show())
  # dispatcher.register(Summary())

  ShellHandler(dispatcher).cmdloop()

