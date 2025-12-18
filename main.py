"""
TODO: Add support for missing CONNECT INDICATOR
"""

import os
import cmd
import argparse
from rich.console import Console
from rich.table import Table
from scapy.all import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

console = Console()

BT_ATT_Read_Request   = 0xa
BT_ATT_Read_Response  = 0xb
BT_ATT_Write_Request  = 0x12
BT_ATT_Write_Response = 0x13
BT_ATT_Write_Command  = 0x52

def printable(s):
  pchar = lambda a: chr(a) if 32 <= a < 127 else '.'
  return ''.join([pchar(a) for a in s])

def hexline(s, bytes_per_group=8):
  chunks = []
  for i in range(0, len(s), bytes_per_group):
      chunks.append(' '.join([f'{c:02x}' for c in s[i:i+bytes_per_group]]))
  return '  '.join(chunks)

def hexdump(s, bytes_per_line=16, bytes_per_group=8):
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



class BLEConnection:
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

class BTCap:
  def __init__(self):
    self.pcap_file = None
    self.pcap_file_len = 0
    self.encrypted = False
    self.att_seen = False
    self.connections = {}
    self.conn_counter = 0
  
  def get_connection_by_idx(self, idx) -> BLEConnection | None:
    conn_keys = self.connections.keys()
    if idx > len(conn_keys):
      console.print(f"[X] Error. Invalid index: {idx}", style="red")
      return None    
    for i, aa in enumerate(conn_keys):
      if i == idx:
        return self.connections[aa]
    return None
  
  def get_connection_by_aa(self, access_address:str) -> BLEConnection | None:
    try:
      access_address = access_address.lower()
      if access_address.startswith("0x"):
        access_address = access_address.replace("0x", "")
      return self.connections[int(access_address, 16)]
    except Exception as e:
      console.print(f"[X] Error. Invalid access address: {e}", style="red")
    
  def open(self, file_path:str|None=None ) -> bool:
    if os.path.exists(file_path):
      self.pcap_file = rdpcap(file_path)
      self.pcap_file_len = len(self.pcap_file)
      return True
    return False
  
  def analyze_encryption(self) -> None:
    for pkt in self.pcap_file:
      if pkt.haslayer(HCI_Event_Encryption_Change):
        if pkt.encryption_enabled == 1:
          self.encrypted = True

      if pkt.haslayer(ATT_Hdr):
        self.att_seen = True
      
      if self.encrypted and self.att_seen:
        break
  
  def show_encryption_header(self):
    if not self.encrypted and self.att_seen:
      console.print(f"[*] Captured file [green]Decrypted[/green]")
    elif self.encrypted:
      console.print(f"[X] Captured file [red]Encrypted[/red]")
    else:
      console.print(f"[-] Captured file [yellow]Unknown[/yellow]")
  
  def group_connections(self):
    for idx, pkt in enumerate(self.pcap_file):
      pkt_index = idx + 1
      if pkt.haslayer(BTLE_CONNECT_REQ):
        packet_req = pkt.getlayer(BTLE_CONNECT_REQ)
        # Check if the next packet can be a connection follow indicator
        next_packet = self.pcap_file[idx+1]
        if next_packet.haslayer(BTLE_CTRL):
          if next_packet.getlayer(BTLE_CTRL).opcode == 12 or next_packet.getlayer(BTLE_CTRL).opcode == 8:
            aa = next_packet.access_addr
            conn = BLEConnection(conn_id=self.conn_counter, access_address=aa, start_pkt=pkt_index, source=packet_req.InitA, destination=packet_req.AdvA)
            self.connections[aa] = conn
            console.print(f"[*] Detected: CONNECT IND | Connection #{conn.id} Source={packet_req.InitA} Destination={packet_req.AdvA} Access Address={hex(aa)} pkt={pkt_index}")
            self.conn_counter += 1
      elif pkt.haslayer(BTLE_CTRL):
        if pkt.haslayer(LL_TERMINATE_IND):
          self.connections[packet_btle.access_addr].terminate_connection(pkt_index)
      elif pkt.haslayer(BTLE_DATA):
        packet_btle = pkt.getlayer(BTLE)
        if packet_btle.access_addr in self.connections:
          self.connections[packet_btle.access_addr].add_packet(pkt_index, pkt)

  def get_packet_by_idx(self, idx):
    if idx < 0 or idx > self.pcap_file_len:
      console.print(f"[X] Error. Invalid index: {idx}", style="red")
      return None
    else:
      return self.pcap_file[idx]

  def show_packet(self, idx):
    if idx < 0 or idx > self.pcap_file_len:
      console.print(f"[X] Error. Invalid index: {idx}", style="red")
    else:
      console.print(f"Packet Information=========================\n")
      console.print(self.pcap_file[idx].show())

  def show_connections(self):
    table = Table(title="[bold]BLE Connections Summary[/bold]", expand=True)
    table.add_column("No.")
    table.add_column("Access Address")
    table.add_column("Packets")
    table.add_column("Status")
    
    for aa, conn in self.connections.items():
      status = "CLOSED" if conn.terminated else "OPEN"
      table.add_row(str(conn.id), str(hex(aa)), str(len(conn.packets)), status)
    console.print(table)


class BTCapDissector:
  def __init__(self, bt_connection: BLEConnection):
    self.bt_connection = bt_connection
  
  def show_connection_information(self):
    table = Table(title=f"Connection {self.bt_connection.id}")
    table.add_column("ID")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Access Address")
    table.add_column("Start Packet")
    table.add_column("End Packet")
    table.add_column("Status")
    status = "CLOSED" if self.bt_connection.terminated else "OPEN"
    table.add_row(str(self.bt_connection.id), self.bt_connection.source, self.bt_connection.destination, str(hex(self.bt_connection.access_address)), str(self.bt_connection.start_pkt), str(self.bt_connection.end_pkt), status)
    console.print(table)
  
  def show_read_packets(self, idx, packet):
    if packet.haslayer(ATT_Hdr):
      if packet.opcode == BT_ATT_Read_Request:
        console.print(f"[READ_REQUEST  - {idx}] RF Channel: {packet.rf_channel} \tRSSI: {packet.signal} \tGATT Handler: {hex(packet.gatt_handle)}")
      elif packet.opcode == BT_ATT_Read_Response:
        console.print(f"[READ_RESPONSE - {idx}] RF Channel: {packet.rf_channel} \tRSSI: {packet.signal} \tValue: {packet.value}")

  def show_write_packets(self, idx, packet):
    if packet.haslayer(ATT_Hdr):
      if packet.opcode == BT_ATT_Write_Request:
        console.print(f"[WRITE_REQUEST  - {idx}] RF Channel: {packet.rf_channel} \tRSSI: {packet.signal} \tGATT Handler: {hex(packet.gatt_handle)}")
      elif packet.opcode == BT_ATT_Write_Response:
        console.print(f"[WRITE_RESPONSE - {idx}] RF Channel: {packet.rf_channel} \tRSSI: {packet.signal} \tValue:")
      elif packet.opcode == BT_ATT_Write_Command:
        console.print(f"[WRITE_COMMAND  - {idx}] RF Channel: {packet.rf_channel} \tRSSI: {packet.signal} \tGATT Handler: {hex(packet.gatt_handle)} Bytes: {packet.data} HEX: {packet.data.hex()}")
  
  def show_generic_packet(self, idx, packet):
    console.print(f"[READ_RESPONSE - {idx}] RF Channel: {packet.rf_channel} \tRSSI: {packet.signal} \tValue: {packet}")

  def get_packet_information(self, filter="all"):
    self.show_connection_information()
    for pkt in self.bt_connection.packets:
      idx, packet = pkt
      # TODO: Fix the view, only show read then write and show generic too
      if filter == "all" or filter == "":
        self.show_read_packets(idx, packet)
        self.show_write_packets(idx, packet)
        # self.show_generic_packet(idx, packet)
      elif filter == "read":
        self.show_read_packets(idx, packet)
      elif filter == "write":
        self.show_write_packets(idx, packet)
      else:
        console.print(f"[X] Error. invalid filter: {filter}", style="red")
        break

class MainCmd(cmd.Cmd):
  intro = f"BTCap - Type help or ? to list commands.\n"
  prompt = "root >"
  file = None
  doc_header = "Commands"
  misc_header = "Misc Commands"
  undoc_header = "Undocumented Commands"
  
  def __init__(self, completekey = "tab", stdin = None, stdout = None):
    super().__init__(completekey, stdin, stdout)
    self.loaded_file = False
    self.connection_loaded = None
    self.bt = BTCap()
    
  def __validate_file_loaded(self):
    if not self.loaded_file:
      console.print(f"[X] Load document first!", style="red")
    return self.loaded_file
    
  def do_load(self, args):
    """Load PCAP file"""
    # load /Users/astrobyte/Desktop/sniffleLockConnection.pcapng
    # TODO: ADD args validation and path autocomplete
    args = "/Users/astrobyte/Desktop/sniffleLockConnection.pcapng"
    if not self.bt.open(args):
      console.print(f"[X] Can not find the path: {args}", style="red")
      self.loaded_file = False
      return False
    console.print(f"[*] File: {args} loaded successfully", style="green")
    filename = os.path.basename(args)
    self.loaded_file = True
    self.connection_loaded = None
    self.prompt = f"{filename} > "
    self.bt.analyze_encryption()
    self.bt.show_encryption_header()
    self.bt.group_connections()
    self.bt.show_connections()
  
  def do_connections(self, _):
    """Show document connections"""
    if self.__validate_file_loaded():
      self.bt.show_connections()
  
  def do_use(self, args):
    """Set the connection to work with by idx or aa"""
    if self.__validate_file_loaded():
      try:
        conn = self.bt.get_connection_by_idx(int(args))
        if not conn:
          return False
      except Exception as e:
        conn = self.bt.get_connection_by_aa(args)
        if not conn:
          return False
      
      console.print("[*] Connection loaded successfully!", style="green")
      self.connection_loaded = BTCapDissector(conn)
      self.connection_loaded.show_connection_information()
      self.prompt = self.prompt.replace(" > ", "")
      self.prompt = f"{self.prompt} - Conn: {conn.id}> "
    
  def do_show(self, args):
    """Show READ, WRITE o ALL communications packets"""
    if self.__validate_file_loaded():
      # TODO: Add validations for this args
      if self.connection_loaded is None:
        console.print("[X] Error. First select a connection with the 'use' command.", style="red")
        return False
      args = args.lower()
      try:
        self.bt.show_packet(int(args))
      except Exception:
        self.connection_loaded.get_packet_information(args)
  
  def do_get(self, args):
    # TODO: Handle this format to perform more information
    """Show the Selected packet in: Hexdump, plain or bytes. Note only works for read and write cmd"""
    if self.__validate_file_loaded():
      args = args.lower().split()
      idx = int(args[0]) - 1
      packet = self.bt.get_packet_by_idx(idx)
      if packet is None:
        console.print(f"[-] Packet with index: {idx}, not found!", style="yellow")
        return False
      if len(args) == 1:
        print(packet.show())
        return False
      
      txt_format = args[1]
      if txt_format == "plain":
        if packet.data:
            console.print(packet.data.decode("utf-8", errors="replace"))
        elif packet.value:
          console.print(packet.value.decode("utf-8", errors="replace"))
        elif packet.load:
          console.print(packet.load.decode("utf-8", errors="replace"))
        else:
          console.print(f"[-] Packet: {idx}, don't have a valid value field.", style="yellow")
      elif txt_format == "hexdump":
        if packet.data:
          console.print(hexdump(packet.data))
        elif packet.value:
          console.print(hexdump(packet.value))
        elif packet.load:
          console.print(hexdump(packet.load))
        else:
          console.print(f"[-] Packet: {idx}, don't have a valid value field.", style="yellow")
      elif txt_format == "hex":
        if packet.haslayer(ATT_Hdr):
          if packet.data:
            console.print(packet.data.hex())
          elif packet.value:
            console.print(packet.value.hex())
          elif packet.load:
            console.print(packet.load.hex())
          else:
            console.print(f"[-] Packet: {idx}, don't have a valid value field.", style="yellow")
      else:
        console.print(f"[-] Packet with index: {txt_format}, not found!", style="yellow")
          
  
  def do_exit(self, _):
    """Exit app"""
    return True

if __name__ == "__main__":
  parser = argparse.ArgumentParser("BTCap")
  parser.add_argument("--file", "-f", help="Path to file")
  
  args = parser.parse_args()
  bt = BTCap()
  if args.file:
    if not bt.open(args.file):
      console.print(f"[X] Can not find the path: {args.file}", style="red")
      exit()
    bt.analyze_encryption()
    bt.show_encryption_header()
    bt.group_connections()
    
    con1 = bt.get_connection_by_idx(3)
    con2 = bt.get_connection_by_aa("0xaf9aac23")
    BTCapDissector(con1).get_packet_information()
    BTCapDissector(con2).get_packet_information("write")
    bt.show_packet(99)
    bt.show_connections()
  else:
    MainCmd().cmdloop()