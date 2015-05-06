# Copyright 2015
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Implements reliable transport for our PILO messages

"""

from pox.core import core
import pox.lib.packet as pkt

from pox.lib.recoco import Timer
from pox.lib.revent.revent import EventMixin
from pox.lib.revent import Event
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from twisted.internet.protocol import DatagramProtocol
from lib.util import get_hw_addr, get_ip_address
import socket, struct

log = core.getLogger()

class PiloConnectionUp (Event):
  """
  Event raised when the connection to an PILO client has been
  established.
  """
  def __init__ (self, connection):
    Event.__init__(self)
    self.connection = connection
    self.dst_address = connection.config.dst_address

class PiloConnectionDown (Event):
  """
  Event raised when the connection to an PILO client has gone
  down.
  """
  def __init__ (self, connection):
    Event.__init__(self)
    self.connection = connection
    self.dst_address = connection.config.dst_address


class PiloDataIn (Event):
  """
  Event raised when data arrives over pilo tunnel
  """
  def __init__ (self, msg):
    Event.__init__(self)
    self.msg = msg

class PiloPacketIn (Event):
  """
  Event raised when pilo packet comes in from pilo_source_obj
  """
  def __init__ (self, packet):
    Event.__init__(self)
    self.packet = packet


# TODO: replace this with OF out packet thing?
def send_pilo_broadcast(self, packet):
  log.debug('Sending PILO broadcast')
  log.debug(packet)
  packed = packet.pack()

  sock = socket.socket(socket.AF_INET, # IP
      socket.SOCK_DGRAM) # UDP
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
  sock.sendto(packed, (self.udp_ip, self.udp_port))

class PiloTransportConfig (object):
  def __init__ (self, pilo_source_obj, udp_ip, udp_port, src_ip, src_address, retransmission_timeout, heartbeat_interval):
    self.pilo_source_obj = pilo_source_obj
    self.udp_ip = udp_ip
    self.udp_port = udp_port
    self.src_ip = src_ip
    self.src_address = EthAddr(self.src_address)
    self.retransmission_timeout = retransmission_timeout
    self.heartbeat_interval = heartbeat_interval


class PiloTransport (EventMixin):
  _eventMixin_events = set([PiloConnectionUp, PiloConnectionDown, PiloDataIn])

  def __init__ (self, pilo_source_obj, udp_ip, udp_port, src_ip, src_address, retransmission_timeout, heartbeat_interval):
    log.debug('Creating PiloTransport object')
    self.config = PiloTransportConfig(pilo_source_obj, udp_ip, udp_port, src_ip, src_address, retransmission_timeout, heartbeat_interval)
    pilo_source_obj.addListeners()
    self.connections = []
    self.addListeners()

  def __str__ (self):
    string = 'PiloTransport: src_address=' + self.config.src_address +
             ' src_ip=' + self.config.src_ip +
             ' udp_ip=' + self.config.udp_ip +
             ' retransmission_timeout=' + self.config.retransmission_timeout

    if self.connections:
      string += "\nConnections:"
      for connection in self.connections
        string += str(connection) + '\n'

    return string;

  def _handle_PiloConnectionDown (self, event):
    """
    Handles pilo connection down
    """
    connection = event.connection
    self.connections.remove(connection)

  def _handle_PiloPacketIn (self, event):
    """
    Handles pilo packet in messages from our pilo_source_obj (for now pilo_controller or pilo_client)
    """
    pilo_packet = event.packet
    # TODO: Check if actually pilo packet?

    dst_mac = EthAddr(pilo_packet.dst_address)
    src_mac = EthAddr(pilo_packet.src_address)

    if pkt.packet_utils.same_mac(local_mac, src_mac):
      log.debug('This came from us, so we can ignore')
      return

    if pkt.packet_utils.same_mac(dst_mac, local_mac):
      log.debug('This is for us:')
      log.debug(pilo_packet)
      # Find connection with that address
      connection = None
      for con in self.connections:
        if pkt.packet_utils.same_mac(connection.address, pilo_packet.src_address):
          connection = con

      if pilo_packet.SYN and not pilo_packet.ACK:
        if connection:
          return
        new_connection = PiloTransportConnection(self.config, self, pilo_packet.src_address, initiating=False)
        # Add to connections list
        self.connections.append(new_connection)
      else:
        # Any packet that isn't a SYN should be part of a connection
        if not connection:
          return
        connection.handle_packet(pilo_packet)

    else:
      log.debug('Message not for us, let\'s flood it back out')
      # TODO: Memory w/ timer for packets we've already seen?
      pilo_packet.ttl = pilo_packet.ttl - 1
      if pilo_packet.ttl > 0:
        send_pilo_broadcast(pilo_packet)
      else:
        log.debug('TTL expired:')
        log.debug(pilo_packet)

  def initiate_connection (self, dst_address):
    if not isinstance(dst_address, EthAddr):
      dst_address = EthAddr(dst_address)
    new_connection = PiloTransportConnection(self.config, self, pilo_packet.src_address)
    self.connections.append(new_connection)

  def send (self, dst_address, msg):
    assert dst_address
    assert msg

    if not isinstance(dst_address, EthAddr):
      dst_address = EthAddr(dst_address)

    connection = None
      for con in self.connections:
        if pkt.packet_utils.same_mac(connection.address, pilo_packet.src_address):
          connection = con

    assert connection
    connection.send(msg)

  def terminate_connection (self, address):
    for connection in self.connections:
      if pkt.packet_utils.same_mac(connection.dst_address, address):
        # Do we need a callback?
        def _terminate_connection_callback (packet):
          self.connections.remove(connection)

        connection.close(callback=_terminate_connection_callback)


class PiloTransportConnection (object):

  def __init__ (self, config, transport, dst_address, connected=False, initiating=True):
    log.debug('Creating PiloTransport object')
    self.config = config
    self.src_address = config.src_address
    self.transport = transport
    self.connected = connected
    self.in_transit = []
    self.rx_buffer = []
    self.most_recent_rx = None
    self.seq = 0
    self.rx = 0
    self.acked = 0

    if isinstance(dst_address, EthAddr):
      self.dst_address = dst_address
    else:
      self.dst_address = EthAddr(dst_address)

    self.transport.addListeners()

    if not connected:
      if self.initiating:
        # Send SYN in normal pipeline
        self.send(callback=self.synack_callback, SYN=True)
      else:
        # Send SYNACK
        self.send(SYN=True, ACK=True)

    # TODO: will this work? I want to add this class' handlers
    # to its own events...
    # DO I need this?
    self.addListeners()

    self.heartbeat_timer = Timer(self.config.heartbeat_interval, self.check_heartbeat)

  def __str__ (self):
    string = 'PiloTransportConnection: ' +
             ' dst_address = ' + str(self.dst_address) +
             ' connected= ' + str(self.connected) +
             ' initiating= ' + str(self.inititating)
    return string

  def close (callback=None):
    def _fin_callback ():
      self.transport.raiseEventNoErrors(PiloConnectionDown, self)
      if callback:
        callback()

    self.send(callback=_fin_callback, FIN=True)

  def synack_callback (self, packet):
    self.connected = True
    self.transport.raiseEventNoErrors(PiloConnectionUp, self)
    self.ack(pilo_packet)

  def ack (self, packet):
    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = self.config.src_address
    pilo_packet.dst_address  = self.dst_address
    pilo_packet.seq = packet.seq
    pilo_packet.ack = packet.seq + len(packet.pack())
    pilo_packet.ACK = True

    send_pilo_broadcast(pilo_packet)

  def send_finack (self):
    def _finack_callback ():
      self.transport.raiseEventNoErrors(PiloConnectionDown, self)
      if callback:
        callback()

    self.send(callback=_finack_callback, FIN=True, ACK=True)

  def handle_packet_in (self, packet):
    # Handle everything other than SYN only packet
    if packet.FIN:
      self.send_finack()

    if packet.ACK:
      self.handle_ack_in(packet)
      return

    ack_no = packet.seq + len(packet.pack())
    # If this packet matches the connection's rx
    if self.rx == packet.seq:
      # reduce congestion
      # update this connections rx
      self.rx += len(packet.pack())
      # send ack for this packet
      # TODO: would be better to only send one ack for multiple packets to
      self.ack(packet)
      self.most_recent_rx = packet
      # Raise PiloDataIn event so that objects above us know a message has come in
      self.transport.raiseEventNoErrors(PiloDataIn, packet.msg)
      # sort rx_buffer by seq
      self.rx_buffer.sort(key=lambda x: x.seq)

      # call handle_packet_in on first packet in buffer
      try:
        self.handle_packet_in(rx_buffer[0])
      except IndexError:
        # No packets in the rx_buffer
        pass

    # If this packet does not match the sender's seq no
    else:
      # if it's not below current seq no
      if packet.seq > self.rx:
        # ack the current rx
        self.ack(self.most_recent_rx)
        # add this packet to their buffer
        already_buffered = False
        for buffered in rx_buffer:
          if buffered == packet:
            already_buffered = True

        if not already_buffered:
          self.rx_buffer.append(pilo_packet)

  def handle_ack_in (self, ack_packet):

    if not ack_packet.ACK:
      # if for some reason we get a packet here that isn't an ack, return
      return

    log.debug('Handling ack:')
    log.debug(ack_packet)

    log.debug('In transit:')
    # TODO: Potentially add some checksum check
    for sent in self.in_transit:
      packet = sent['packet']
      log.debug(packet)
      if (pkt.packet_utils.same_mac(ack_packet.src_address, packet.dst_address) and
          ack_packet.seq == packet.seq and
          ack_packet.ack == packet.seq + len(packet.pack())):

        self.in_transit.remove(packet)
        if sent['callback']:
          sent['callback'](packet)

  def send (self, msg=None, callback=None **flags):
    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = self.config.src_address
    pilo_packet.dst_address  = self.dst_address

    if flags['ACK']:
      pilo_packet.ACK = True
    if flags['SYN']:
      pilo_packet.SYN = True
    if flags['FIN']:
      pilo_packet.FIN = True
    if flags['HRB']:
      pilo_packet.HRB = True

    if msg:
      pilo_packet.payload = msg

    self.send_packet(pilo_packet, callback=callback)

  def send_packet (self, packet, callback=None):
    packet.seq = self.seq
    self.seq += len(packet.pack())

    send_pilo_broadcast(packet)
    self.in_transit.append({
      'packet':packet,
      'callback': callback
      })
    core.callDelayed(self.retransmission_timeout, self.check_acked, packet)

  def check_acked(self, pilo_packet):
    log.debug('checking if acked:')
    log.debug(pilo_packet)

    log.debug('still in self.in_transit:')
    for sent in self.in_transit:
      packet = sent['packet']
      log.debug(packet)
      log.debug('packet len:' + str(len(packet.pack())))

    log.debug(pilo_packet)
    if pilo_packet in self.in_transit:
      log.debug('is still in transit')
      send_pilo_broadcast(pilo_packet)
      core.callDelayed(self.retransmission_timeout, self.check_acked, pilo_packet)

    else:
      log.debug('is not still in transit')

  def check_heartbeat (self):
    def _heartbeat_acked (packet):
      self.heartbeat_timer = Timer(self.config.heartbeat_interval, self.check_heartbeat)

    self.send(callback=_heartbeat_acked, HRB=True)
    core.callDelayed(self.config.heartbeat_interval, self.heartbeat_timeout)

  def heartbeat_timeout (self):
    log.debug('heartbeat timeout for connection: ' + str(self))
    # TODO: best way to signal connection down here?
    # No need to do any FIN/FINACK I think...
    self.connected = False
    self.transport.raiseEventNoErrors(PiloConnectionDown, self)


