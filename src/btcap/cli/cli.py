#!/usr/bin/venv python
# Copyright 2025 - 2025, Kevin Leon
# SPDX-License-Identifier: GPL-3.0-only
from cli.handler import Context, Command
from cli.bt_sessions import BTFormatPrint, FMTPacket
from rich.console import Console

console = Console()

class Summary(Command):
  name = "summary"
  context = {Context.GLOBAL, Context.SESSION}
  help = "summary"
  
  def run(self, args, state):
    if not state.current_session:
      console.print("[-] Set session first!", style="yellow")
      return
    console.print(BTFormatPrint().show_summary_packets(state.current_session))

class Show(Command):
  name = "show"
  context = {Context.GLOBAL, Context.SESSION}
  help = "show pcap | tree | packet <id>"
  
  def run(self, args, state):
    if not state.current_session:
      console.print("[-] Set session first!", style="yellow")
      return
    if not args:
      console.print("Usage: show pcap | tree | packet <id>")
      return
    option = args[0]
    if option.lower() == "pcap":
      console.print(BTFormatPrint().show_session_fmt_pcap(state.current_session))
    elif option.lower() == "tree":
      console.print(BTFormatPrint().show_session_fmt_tree(state.current_session))
    elif option.lower() == "packet":
      if not args[1]:
        console.print("Usage: show pcap | tree | packet <id>")
        return
      console.print(BTFormatPrint().show_session_packet(state.current_session, int(args[1]), state.view_mode))
    else:
      console.print(BTFormatPrint().show_session_fmt_packet(state.current_session))

class Session(Command):
  name = "session"
  context = {Context.GLOBAL, Context.SESSION}
  help = "session empty | id"
  
  def run(self, args, state):
    if not args:
      console.print(BTFormatPrint().show_connections(state.sessions))
      return
  
    sid = int(args[0])
    if sid not in state.sessions:
      console.print("[X] Invalid session id", style="yellow")
      return
    
    state.current_session = state.sessions[sid]
    console.print(f"[*] Using session {sid}")
    console.print(BTFormatPrint().show_session(state.current_session))
    
  
class Set(Command):
  name = "set"
  context = {Context.GLOBAL, Context.SESSION}
  help = "set view <brief | details | hexdump>"
  
  def run(self, args, state):
    if not args:
      console.print("Usage: set view <brief | details | hexdump>")
      return
  
    option = args[0]
    if option.lower() == "view":
      if not args[1]:
        console.print("Usage: set view <brief | details | hexdump>")
        return
    
      view = args[1]
      if view.lower() == "details":
        state.view_mode = FMTPacket.DETAILS
      elif view.lower() == "hexdump":
        state.view_mode = FMTPacket.HEXDUMP
      else:
        state.view_mode = FMTPacket.BRIEF