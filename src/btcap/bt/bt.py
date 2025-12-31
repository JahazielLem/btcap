from enum import Enum, auto
from scapy.packet import Packet
from scapy.utils import rdpcap
from scapy.all import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

BT_ATT_Read_Request   = 0xa
BT_ATT_Read_Response  = 0xb
BT_ATT_Write_Request  = 0x12
BT_ATT_Write_Response = 0x13
BT_ATT_Write_Command  = 0x52
BT_ATT_Notification   = 0x1b

class BTEventType(Enum):
  # ATT
  ATT_READ_REQ    = auto()
  ATT_READ_RSP    = auto()
  ATT_WRITE_REQ   = auto()
  ATT_WRITE_RSP   = auto()
  ATT_WRITE_CMD   = auto()
  ATT_NOTIFY_RCV  = auto()
  GENERIC         = auto()
  # BT
  LL_CONNECT_ID   = auto()
  LL_TERMINATE_ID = auto()
  BTLE_DATA       = auto()
  ADV             = auto()

class BLEEvent:
  def __init__(self, *, idx, ts, etype, handle=None, value=None, rssi=None, channel=None, raw_pkt=None, aa=None):
    self.idx       = idx
    self.timestamp = ts
    self.handle    = handle
    self.value     = value
    self.rssi      = rssi
    self.raw_pkt   = raw_pkt
    self.type      = etype
    self.channel   = channel
    self.aa = aa
    
    self.parent = None
    self.children = []

class ATTParser:
  @staticmethod
  def parse(idx, pkt):
    opcode = pkt.opcode
    if opcode == BT_ATT_Read_Request:
      etype = BTEventType.ATT_READ_REQ
      handle = pkt.gatt_handle
      value = None
    elif opcode == BT_ATT_Read_Response:
      etype = BTEventType.ATT_READ_RSP
      handle = None
      value = pkt.value
    elif opcode == BT_ATT_Write_Request:
      etype = BTEventType.ATT_WRITE_REQ
      handle = pkt.gatt_handle
      value = pkt.data
    elif opcode == BT_ATT_Write_Response:
      etype = BTEventType.ATT_WRITE_RSP
      handle = None
      value = None
    elif opcode == BT_ATT_Write_Command:
      etype = BTEventType.ATT_WRITE_CMD
      handle = pkt.gatt_handle
      value = pkt.data
    elif opcode == BT_ATT_Notification:
      etype = BTEventType.ATT_NOTIFY_RCV
      handle = pkt.gatt_handle
      value = pkt.value
    else:
      etype = BTEventType.GENERIC
      handle = None
      value = None
    return BLEEvent(idx=idx, ts=pkt.time, etype=etype, handle=handle, value=value, rssi=pkt.signal, channel=pkt.rf_channel, raw_pkt=pkt)

class BLEConnection:
  def __init__(self, cid, aa, start_idx, start_ts):
    self.id = cid
    self.aa = aa
    self.start_idx = start_idx
    self.start_ts = start_ts
    self.end_idx = None
    self.end_ts = None
    
    self.events = []
    self.active = True
  
  def add_event(self, evt: BLEEvent):
    evt.parent = self
    self.events.append(evt)
  
  def close(self, idx, ts):
    self.end_idx = idx
    self.end_ts = ts
    self.active = False
  
  def _correlate(self):
    pending = []
    for ev in self.events:
      if ev.type in (
        BTEventType.ATT_READ_REQ,
        BTEventType.ATT_WRITE_REQ,
      ):
        pending.append(ev)
      elif ev.type in (BTEventType.ATT_READ_RSP, BTEventType.ATT_WRITE_RSP):
        if pending:
          req = pending.pop(0)
          req.children.append(ev)
          ev.parent = req

class BTConnection:
  def __init__(self, filepath):
    self.path = filepath
    self.connections = {}       # id -> BLEConnection
    self.aa_to_id = {}          # aa -> id
    self.next_id = 0            # contador incremental
    self.raw_packets = None
    self._parse()
  
  def get_connections(self):
    return self.connections
  
  def get_connection(self, cid: int) -> BLEConnection | None:
    return self.connections.get(cid)

  def get_connection_count(self) -> int:
    return len(self.connections)

  def get_raw_packets_count(self) -> int:
    return len(self.raw_packets)

  def _get_or_create_conn(self, aa, idx, ts):
    if aa in self.aa_to_id:
      cid = self.aa_to_id[aa]
      return self.connections[cid]

    cid = self.next_id
    self.next_id += 1

    conn = BLEConnection(
      cid=cid,
      aa=aa,
      start_idx=idx,
      start_ts=ts
    )

    self.connections[cid] = conn
    self.aa_to_id[aa] = cid
    return conn
  
  def _search_match_packet(self, packets, start_idx, end_idx=5):
    for i in range(start_idx, (start_idx + end_idx)):
      next_pkt = packets[i]
      if next_pkt.haslayer(BTLE_CTRL):
        if next_pkt.getlayer(BTLE_CTRL).opcode == 12 or next_pkt.getlayer(BTLE_CTRL).opcode == 8:
          return next_pkt
    return None

  def _parse(self):
    self.raw_packets = rdpcap(str(self.path))
    for i, pkt in enumerate(self.raw_packets):
      # CONNECT_IND
      if pkt.haslayer(BTLE_CONNECT_REQ):
        if i >= len(self.raw_packets):
          continue
        match_pkt = self._search_match_packet(self.raw_packets, i)
        if match_pkt:
          aa = match_pkt.access_addr
        else:
          aa = pkt.getlayer(BTLE_CTRL).access_addr
        conn = self._get_or_create_conn(aa, i, pkt.time)
        evt = BLEEvent(
          idx=i,
          ts=pkt.time,
          etype=BTEventType.LL_CONNECT_ID,
          raw_pkt=pkt,
          aa=aa
        )
        conn.add_event(evt)
        continue
      # TERMINATE_IND
      if pkt.haslayer(BTLE_CTRL): 
        if pkt.haslayer(LL_TERMINATE_IND):
          aa = pkt.getlayer(BTLE).access_addr
          cid = self.aa_to_id[aa]
          conn = self.connections[cid]
          if conn:
            evt = BLEEvent(
              idx=i,
              ts=pkt.time,
              etype=BTEventType.LL_TERMINATE_ID,
              raw_pkt=pkt,
              aa=aa
            )
            conn.add_event(evt)
            conn.close(i, pkt.time)
          continue
      if pkt.haslayer(BTLE_DATA):
        btle = pkt.getlayer(BTLE)
        aa = btle.access_addr

        conn = self._get_or_create_conn(aa, i, pkt.time)

        if pkt.haslayer(ATT_Hdr):
          evt = ATTParser.parse(i, pkt)
          evt.raw_pkt = pkt
          evt.aa = aa
        else:
          evt = BLEEvent(
            idx=i,
            ts=pkt.time,
            etype=BTEventType.BTLE_DATA,
            raw_pkt=pkt,
            aa=aa
          )

        conn.add_event(evt)
        continue
    for aa in self.connections:
      conn = self.connections[aa]
      conn._correlate()
      
    return self.connections