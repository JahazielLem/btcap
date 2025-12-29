#!/usr/bin/venv python
# Copyright 2025 - 2025, Kevin Leon
# SPDX-License-Identifier: GPL-3.0-only

from enum import Enum, auto
from pathlib import Path
from scapy.packet import Packet
from scapy.utils import rdpcap
from scapy.all import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from rich.table import Table
from rich.tree import Tree
from rich.console import Console

console = Console()

BT_ATT_Read_Request   = 0xa
BT_ATT_Read_Response  = 0xb
BT_ATT_Write_Request  = 0x12
BT_ATT_Write_Response = 0x13
BT_ATT_Write_Command  = 0x52
BT_ATT_Notification   = 0x1b

class FMTPacket(Enum):
  BRIEF   = auto()
  DETAILS = auto()
  HEXDUMP = auto()

class BLEEventType(Enum):
  ATT_READ_REQ    = auto()
  ATT_READ_RSP    = auto()
  ATT_WRITE_REQ   = auto()
  ATT_WRITE_RSP   = auto()
  ATT_WRITE_CMD   = auto()
  ATT_NOTIFY_RCV  = auto()
  LL_CONNECT_ID   = auto()
  LL_TERMINATE_ID = auto()
  GENERIC         = auto()

def printable(s):
  pchar = lambda a: chr(a) if 32 <= a < 127 else '.'
  return ''.join([pchar(a) for a in s])

def hexline(s, bytes_per_group=8):
  chunks = []
  for i in range(0, len(s), bytes_per_group):
      chunks.append(' '.join([f'{c:02x}' for c in s[i:i+bytes_per_group]]))
  return '  '.join(chunks)

def hexdump_ev(s, bytes_per_line=16, bytes_per_group=8):
  prev_chunk = None
  in_repeat = False
  hexline_len = 3*bytes_per_line + bytes_per_line//bytes_per_group - 2
  lines = []
  for i in range(0, len(s), bytes_per_line):
    chunk = s[i:i+bytes_per_line]
    if chunk == prev_chunk and i + bytes_per_line < len(s):
      if not in_repeat:
        lines.append('*')
        in_repeat = True
    else:
      lines.append(f'0x{i:04x}:  {hexline(chunk, bytes_per_group):{hexline_len}}  {printable(chunk)}')
      in_repeat = False
    prev_chunk = chunk
  return '\n'.join(lines)


class BLEEvent:
  def __init__(self, *, idx, ts, etype, handle=None, value=None, rssi=None, channel=None, raw_pkt=None):
    self.idx = idx
    self.timestamp = ts
    self.type: BLEEventType = etype
    self.handle = handle
    self.value = value
    self.rssi = rssi
    self.channel: int = channel
    self.raw_pkt = raw_pkt
    
    self.parent = None
    self.children = []
  
class BTSession:
  def __init__(self, conn_id, access_address, start_pkt, source, destination):
    self.id             = conn_id
    self.source         = source
    self.destination    = destination
    self.access_address = access_address
    self.start_pkt      = start_pkt
    self.end_pkt        = None
    self.packets        = []
    self.terminated     = False
  
  def add_packet(self, packet_idx, packet):
    self.packets.append((packet_idx, packet))
  
  def terminate_connection(self, packet_idx):
    self.terminated = True
    self.end_pkt = packet_idx
  
  def get_packet_by_idx(self, idx) -> Packet | None:
    for i, pkt in self.packets:
      if i == idx:
        return pkt
    return None

class BTContext:
  def __init__(self, path: Path):
    self.pcap_path: Path = path
    self.session_counter: int = 0
    self.connections_by_aa = {}
    self.connections_by_id = {}
    self.packets: list[Packet] = self.dissect()
  
  def dissect(self) -> list[Packet]:
    scapy_data = rdpcap(str(self.pcap_path))
    for idx, pkt in enumerate(scapy_data):
      pkt_index = idx + 1
      if pkt.haslayer(BTLE_CONNECT_REQ):
        packet_req = pkt.getlayer(BTLE_CONNECT_REQ)
        if pkt_index >= len(scapy_data):
          continue
        next_packet = scapy_data[idx+1]
        if next_packet.haslayer(BTLE_CTRL):
          if next_packet.getlayer(BTLE_CTRL).opcode == 12 or next_packet.getlayer(BTLE_CTRL).opcode == 8:
            aa = next_packet.access_addr
            session = BTSession(
              conn_id        = self.session_counter,
              access_address = aa,
              start_pkt      = pkt_index,
              source         = packet_req.InitA,
              destination    = packet_req.AdvA
            )
            
            self.connections_by_aa[aa] = session
            self.connections_by_id[session.id] = session
            self.session_counter += 1
      elif pkt.haslayer(BTLE_CTRL):
        if pkt.haslayer(LL_TERMINATE_IND):
          packet_btle = pkt.getlayer(BTLE)
          aa = packet_btle.access_addr
          if aa in self.connections_by_aa:
            self.connections_by_aa[aa].terminate_connection(pkt_index)
      elif pkt.haslayer(BTLE_DATA):
        packet_btle = pkt.getlayer(BTLE)
        if packet_btle.access_addr in self.connections_by_aa:
          self.connections_by_aa[packet_btle.access_addr].add_packet(pkt_index, pkt)
    return scapy_data
  
  def get_sessions(self) -> dict:
    return self.connections_by_id

  def _parse_att(self, idx, pkt) -> BLEEvent:
    opcode = pkt.opcode
    if opcode == BT_ATT_Read_Request:
      etype = BLEEventType.ATT_READ_REQ
      handle = pkt.gatt_handle
      value = None
    elif opcode == BT_ATT_Read_Response:
      etype = BLEEventType.ATT_READ_RSP
      handle = None
      value = pkt.value
    elif opcode == BT_ATT_Write_Request:
      etype = BLEEventType.ATT_WRITE_REQ
      handle = pkt.gatt_handle
      value = pkt.data
    elif opcode == BT_ATT_Write_Response:
      etype = BLEEventType.ATT_WRITE_RSP
      handle = None
      value = None
    elif opcode == BT_ATT_Write_Command:
      etype = BLEEventType.ATT_WRITE_CMD
      handle = pkt.gatt_handle
      value = pkt.data
    elif opcode == BT_ATT_Notification:
      etype = BLEEventType.ATT_NOTIFY_RCV
      handle = pkt.gatt_handle
      value = pkt.value
    else:
      etype = BLEEventType.GENERIC
      handle = None
      value = None
    return BLEEvent(idx=idx, ts=pkt.time, etype=etype, handle=handle, value=value, rssi=pkt.signal, channel=pkt.rf_channel, raw_pkt=pkt)

class BTSessionDissector:
  def __init__(self, session: BTSession):
    self.session = session
    self.events: list[BLEEvent] = []
    self._parse_packets()
    self._correlate()
  
  def _parse_packets(self):
    if self.session.start_pkt:
      self.events.append(BLEEvent(idx=self.session.start_pkt, ts=None, etype=BLEEventType.LL_CONNECT_ID, raw_pkt=None))
    for idx, pkt in self.session.packets:
      if pkt.haslayer(ATT_Hdr):
        self.events.append(self._parse_att(idx, pkt))
      else:
        self.events.append(BLEEvent(idx=idx, ts=pkt.time, etype=BLEEventType.GENERIC, raw_pkt=pkt))
    if self.session.terminated:
      self.events.append(BLEEvent(idx=self.session.end_pkt, ts=None, etype=BLEEventType.LL_TERMINATE_ID, raw_pkt=None))
  
  def _parse_att(self, idx, pkt):
    opcode = pkt.opcode
    if opcode == BT_ATT_Read_Request:
      etype = BLEEventType.ATT_READ_REQ
      handle = pkt.gatt_handle
      value = None
    elif opcode == BT_ATT_Read_Response:
      etype = BLEEventType.ATT_READ_RSP
      handle = None
      value = pkt.value
    elif opcode == BT_ATT_Write_Request:
      etype = BLEEventType.ATT_WRITE_REQ
      handle = pkt.gatt_handle
      value = pkt.data
    elif opcode == BT_ATT_Write_Response:
      etype = BLEEventType.ATT_WRITE_RSP
      handle = None
      value = None
    elif opcode == BT_ATT_Write_Command:
      etype = BLEEventType.ATT_WRITE_CMD
      handle = pkt.gatt_handle
      value = pkt.data
    elif opcode == BT_ATT_Notification:
      etype = BLEEventType.ATT_NOTIFY_RCV
      handle = pkt.gatt_handle
      value = pkt.value
    else:
      etype = BLEEventType.GENERIC
      handle = None
      value = None
    return BLEEvent(idx=idx, ts=pkt.time, etype=etype, handle=handle, value=value, rssi=pkt.signal, channel=pkt.rf_channel, raw_pkt=pkt)
  
  def _correlate(self):
    pending = []
    for ev in self.events:
      if ev.type in (
        BLEEventType.ATT_READ_REQ,
        BLEEventType.ATT_WRITE_REQ,
      ):
        pending.append(ev)
      elif ev.type in (BLEEventType.ATT_READ_RSP, BLEEventType.ATT_WRITE_RSP):
        if pending:
          req = pending.pop(0)
          req.children.append(ev)
          ev.parent = req

class BTFormatPrint:
  def __init__(self):
    pass

  def _fmt_event(self, ev: BLEEvent):
    base = f"[{ev.idx}] {ev.type.name}"
    if ev.handle:
      base += f" handle={hex(ev.handle)}"
    if ev.value:
      base += f" value={ev.value.hex()} | value= {ev.value.decode('utf-8', errors='replace')}"
    return base
  
  def show_connections(self, sessions):
    table = Table(title="[bold]BLE Connections Summary[/bold]", row_styles=["dim", ""])
    table.add_column("No.")
    table.add_column("Access Address")
    table.add_column("Packets")
    table.add_column("Status")
    
    for aa, conn in sessions.items():
      status = "[green]CLOSED[/green]" if conn.terminated else "[yellow]OPEN[/yellow]"
      table.add_row(str(conn.id), str(hex(aa)), str(len(conn.packets)), status)
    return table
  
  def show_session(self, session: BTSession):
    table = Table(title=f"[bold]Session {session.id}[/bold]")
    table.add_column("ID")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Access Address")
    table.add_column("Start Packet")
    table.add_column("End Packet")
    table.add_column("Status")
    status = "CLOSED" if session.terminated else "OPEN"
    table.add_row(str(session.id), session.source, session.destination, str(hex(session.access_address)), str(session.start_pkt), str(session.end_pkt), status)    
    return table
  
  def show_session_fmt_pcap(self, session: BTSession):
    for idx, pkt in session.packets:
      console.print(f"[{idx}] \t{pkt.summary()}")
  
  def show_session_fmt_tree(self, session: BTSession):
    dissector = BTSessionDissector(session=session)
    root = Tree(f"Connection {session.id}")
    for ev in dissector.events:
      if ev.parent:
        continue

      node = root.add(self._fmt_event(ev))
      for child in ev.children:
        node.add(self._fmt_event(child))
    console.print(root)
  
  def show_session_fmt_packet(self, session: BTSession):
    dissector = BTSessionDissector(session=session)
    for ev in dissector.events:
      console.print(f"[{ev.idx}] \tType: {ev.type} \tTimestamp: {ev.timestamp}\n\tRSSI: {ev.rssi}\n\tChannel: {ev.channel}\n\tType: {ev.type}\n")
    
  def show_session_packet(self, session: BTSession, idx, fmt: FMTPacket = FMTPacket.BRIEF):
    dissector = BTSessionDissector(session=session)
    for ev in dissector.events:
      if ev.idx == idx:
        console.print(self._packet_fmt_handler(ev, fmt))
        return
    console.print(f"[-] Invalid index: {idx}", style="yellow")
  
  def _packet_fmt_handler(self, ev: BLEEvent, fmt: FMTPacket) -> str:
    if fmt == FMTPacket.DETAILS:
     return ev.raw_pkt.show()
    elif fmt == FMTPacket.HEXDUMP:
      sfmt = f"[{ev.idx}] Timestamp: {ev.timestamp} \tChannel: {ev.channel} \tRSSI: {ev.rssi}\n====== Packet Hexdump{hexdump(ev.raw_pkt, dump=True)}"
      if ev.value:
        sfmt += f"\n====== Value Hexdump: {ev.value.hex()}\n{hexdump_ev(ev.value)}"
      return sfmt
    else:
      return self._fmt_event(ev)
  
  def show_summary_packets(self, session: BTSession, filter="all"):
    table = Table(title=f"[bold]Summary Session: {session.id}[/bold]", row_styles=["dim", ""])
    table.add_column("Packet No.")
    table.add_column("Event")
    table.add_column("Handle")
    table.add_column("Value")
    dissector = BTSessionDissector(session=session)
    for ev in dissector.events:
      if ev.type != BLEEventType.GENERIC:
        handle = ""
        if ev.handle:
          handle = str(hex(ev.handle))
        
        value = ""
        if ev.value:
          value = str(ev.value.hex())
        
        table.add_row(str(ev.idx), str(ev.type.name), handle, value)
    
    return table