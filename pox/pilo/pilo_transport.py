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
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ETHER_BROADCAST

from pox.lib.recoco import Timer
from pox.lib.revent.revent import EventMixin
from pox.lib.revent import Event
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from twisted.internet.protocol import DatagramProtocol
from lib.util import get_hw_addr, get_ip_address
import socket, struct
import binascii
import traceback

log = core.getLogger()

class PiloConnectionUp (Event):
  """
  Event raised when the connection to an PILO client has been
  established.
  """
  def __init__ (self, connection):
    Event.__init__(self)
    self.connection = connection
    self.dst_address = connection.dst_address

class PiloConnectionDown (Event):
  """
  Event raised when the connection to an PILO client has gone
  down.
  """
  def __init__ (self, connection):
    Event.__init__(self)
    self.connection = connection
    self.dst_address = connection.dst_address


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
  def __init__ (self, packet, ofp, eth_packet):
    Event.__init__(self)
    self.packet = packet
    self.ofp = ofp
    self.eth_packet = eth_packet


class PiloTransportConfig (object):
  def __init__ (self, pilo_source_obj, udp_ip, udp_port, src_ip, src_address, retransmission_timeout, heartbeat_interval):
    self.pilo_source_obj = pilo_source_obj
    self.udp_ip = udp_ip
    self.udp_port = udp_port
    self.src_ip = src_ip
    self.src_address = EthAddr(src_address)
    self.retransmission_timeout = retransmission_timeout
    self.heartbeat_interval = heartbeat_interval

  def __str__ (self):
    string = """PiloTransportConfig: src_address={src_address}
                udp_port={udp_port}
                src_ip={src_ip}
                udp_ip={udp_ip}
                heartbeat_interval={heartbeat_interval}
                retransmission_timeout={retransmission_timeout}
             """.format(src_address=self.src_address,
                        udp_port=self.udp_port,
                        src_ip=self.src_ip,
                        udp_ip=self.udp_ip,
                        heartbeat_interval=self.heartbeat_interval,
                        retransmission_timeout=self.retransmission_timeout)

    return string



class PiloTransport (EventMixin):
  _eventMixin_events = set([PiloConnectionUp, PiloConnectionDown, PiloDataIn])

  def __init__ (self, pilo_source_obj, udp_ip, udp_port, src_ip, src_address, retransmission_timeout, heartbeat_interval):
    self.config = PiloTransportConfig(pilo_source_obj, udp_ip, udp_port, src_ip, src_address, retransmission_timeout, heartbeat_interval)
    pilo_source_obj.addListeners(self)
    self.connections = []
    self.addListeners(self)

  def __str__ (self):
    string = """PiloTransport: src_address={src_address}
                src_ip={src_ip}
                udp_ip={udp_ip}
                retransmission_timeout={retransmission_timeout}
             """.format(src_address=self.config.src_address,
                        src_ip=self.config.src_ip,
                        udp_ip=self.config.udp_ip,
                        retransmission_timeout=self.config.retransmission_timeout)

    if self.connections:
      string += "\nConnections:"
      for connection in self.connections:
        string += str(connection) + '\n'

    return string;

  # TODO: replace this with OF out packet thing?
  def send_pilo_broadcast (self, packet, ofp=None):
    log.debug('Sending PILO broadcast')
    log.debug(packet)
    packed = packet.pack()

    if ofp:
      try:
        # TODO: Start from here!
        udp_packet = pkt.udp(srcport=self.config.udp_port, dstport=self.config.udp_port)
        udp_packet.set_payload(packed)
        ip_packet = pkt.ipv4(protocol = pkt.ipv4.UDP_PROTOCOL, dstip=IPAddr(self.config.udp_ip))
        ip_packet.set_payload(udp_packet)
        ethernet_packet = pkt.ethernet(type=pkt.ethernet.IP_TYPE, src=self.config.src_address, dst=ETHER_BROADCAST)
        ethernet_packet.set_payload(ip_packet)
        log.debug('using OVS to send broadcast')
        # log.debug('ethernet:')
        # log.debug(ethernet_packet)
        # log.debug('ip:')
        # log.debug(ip_packet)
        # log.debug('udp:')
        # log.debug(udp_packet)
        broadcast = of.ofp_packet_out()
        broadcast.data = ethernet_packet
        broadcast.in_port = ofp.in_port
        broadcast.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        self.config.pilo_source_obj.connection.send(broadcast)

      except Exception as e:
        log.debug('Exception:')
        traceback.print_exc()
        log.debug(e)
        log.debug('config:')
        log.debug(str(self.config))
        log.debug('Can\'t send ovs message')

    else:
      sock = socket.socket(socket.AF_INET, # IP
          socket.SOCK_DGRAM) # UDP
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
      sock.sendto(packed, (self.config.udp_ip, self.config.udp_port))


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

    if pkt.packet_utils.same_mac(self.config.src_address, src_mac):
      log.debug('This came from us, so we can ignore')
      return

    if pkt.packet_utils.same_mac(dst_mac, self.config.src_address):
      log.debug('This is for us:')
      log.debug(pilo_packet)
      # Find connection with that address
      connection = None
      for con in self.connections:
        if pkt.packet_utils.same_mac(con.dst_address, pilo_packet.src_address):
          connection = con

      if pilo_packet.SYN and not pilo_packet.ACK:
        if connection:
          connection.send_synack()
          return
        packet_len = len(pilo_packet.pack())
        new_connection = PiloTransportConnection(self.config, self, pilo_packet.src_address, rx_seq=1, initiating=False)
        # Add to connections list
        self.connections.append(new_connection)
      else:
        # Any packet that isn't a SYN should be part of a connection
        if not connection:
          return

        try:
          connection.handle_packet_in(pilo_packet)

        except Exception as e:
          log.debug('Exception:')
          log.debug(traceback.format_exc())
          log.debug(e)
          log.debug('connection.handle_packet_in failed')

    else:
      log.debug('Message not for us, let\'s flood it back out')
      # TODO: We don't want to send this back on the port it came from!
      # TODO: Memory w/ timer for packets we've already seen?
      pilo_packet.ttl = pilo_packet.ttl - 1
      if pilo_packet.ttl > 0:
        self.send_pilo_broadcast(pilo_packet, ofp=event.ofp)
      else:
        log.debug('TTL expired:')
        log.debug(pilo_packet)

  def initiate_connection (self, dst_address):
    if not isinstance(dst_address, EthAddr):
      dst_address = EthAddr(dst_address)
    new_connection = PiloTransportConnection(self.config, self, dst_address)
    self.connections.append(new_connection)

  def send (self, dst_address, msg):
    assert dst_address
    assert msg

    if not isinstance(dst_address, EthAddr):
      dst_address = EthAddr(dst_address)

    connection = None
    for con in self.connections:
      if pkt.packet_utils.same_mac(connection.dst_address, dst_address):
        connection = con

    assert connection
    connection.send(msg)

  def terminate_connection (self, address, callback=None):
    for connection in self.connections:
      if pkt.packet_utils.same_mac(connection.dst_address, address):
        # Do we need a callback?
        def _terminate_connection_callback (packet):
          self.connections.remove(connection)
          if callback:
            callback(packet)

        connection.close(callback=_terminate_connection_callback)


class PiloTransportConnection (EventMixin):
  _eventMixin_events = set([PiloDataIn])

  def __init__ (self, config, transport, dst_address, connected=False, initiating=True, rx_seq=0):
    log.debug('Creating PiloTransport object')
    self.config = config
    self.transport = transport
    self.connected = connected
    self.initiating = initiating
    self.ack_timers = []
    self.in_transit = {}
    self.rx_buffer = []
    self.most_recent_rx = None
    self.tx_seq = 0
    self.tx_hrb_seq = 0
    self.rx_hrb_seq = 0
    self.rx_seq = rx_seq
    self.acked = 0

    if isinstance(dst_address, EthAddr):
      self.dst_address = dst_address
    else:
      self.dst_address = EthAddr(dst_address)

    self.transport.addListeners(self)

    if not connected:
      if self.initiating:
        # Send SYN in normal pipeline
        self.send(callback=self.synack_callback, seq=0, SYN=True)
      else:
        # Send SYNACK
        self.send_synack()

    self.heartbeat_timer = Timer(self.config.heartbeat_interval, self.check_heartbeat)

  def __str__ (self):
    string = """PiloTransportConnection:
                dst_address = {dst_address}
                connected = {connected}
                initiating = {initiating}
             """.format(dst_address=(self.dst_address),
                        connected=str(self.connected),
                        initiating=str(self.initiating))

    return string

  def close (self, callback=None):
    def _fin_callback ():
      self.transport.raiseEvent(PiloConnectionDown, self)
      self.cleanup()
      if callback:
        callback()

    self.send(callback=_fin_callback, FIN=True)

  def send_synack (self):
    packet = pkt.pilo()
    packet.src_address  = self.config.src_address
    packet.dst_address  = self.dst_address
    packet.seq = self.tx_seq
    packet.ack = packet.seq + 1
    packet.ACK = True
    packet.SYN = True

    self.send_packet(packet, callback=self.synackack_callback)

  # TODO: Better naming!
  def synackack_callback (self, packet):
    """
    For when we've gotten an ACK for our SYNACK
    """
    self.ack(packet)
    if not self.connected:
      self.connected = True
      self.transport.raiseEvent(PiloConnectionUp, self)

  def synack_callback (self, packet):
    """
    For when we've gotten a SYNACK for our SYN
    """
    self.ack(packet)
    if not self.connected:
      self.connected = True
      self.transport.raiseEvent(PiloConnectionUp, self)


  def ack (self, packet, **flags):
    log.debug('Acking packet:')
    log.debug(packet)

    partial_acks = []
    for buffered in self.rx_buffer:
      partial_acks.append(buffered.seq + 1)

    ack_packet = pkt.pilo()
    ack_packet.set_partial_acks(partial_acks)
    ack_packet.src_address  = self.config.src_address
    ack_packet.dst_address  = self.dst_address
    ack_packet.ACK = True

    try:
      if flags['HRB']:
        ack_packet.HRB = True
    except KeyError:
      pass

    ack_packet.seq = packet.seq
    ack_packet.ack = packet.seq + 1

    self.transport.send_pilo_broadcast(ack_packet)

  def send_finack (self):
    def _finack_callback ():
      self.transport.raiseEvent(PiloConnectionDown, self)
      if callback:
        callback()

    self.send(callback=_finack_callback, FIN=True, ACK=True)

  def handle_packet_in (self, packet):
    log.debug('handle_packet_in')
    log.debug(packet)
    # Handle everything other than SYN only packet
    if packet.FIN:
      self.send_finack()

    if packet.ACK:
      self.handle_ack_in(packet)
      return

    if packet.HRB:
      self.handle_heartbeat_in(packet)
      return

    # If this packet matches the connection's rx_seq
    if self.rx_seq == packet.seq:
      last_packet = packet
      log.debug('Matches rx_seq')
      rx_pipeline = [packet]
      self.rx_seq += 1
      self.rx_buffer.sort(key=lambda x: x.seq)
      for buffered in self.rx_buffer:
        if self.rx_seq == buffered.seq:
          rx_pipeline.append(buffered)
          last_packet = buffered
          self.rx_seq += 1

      self.ack(last_packet)
      self.most_recent_rx = last_packet

      rx_pipeline.sort(key=lambda x: x.seq)
      for pipelined in rx_pipeline:
        is_data_in = True

        if pipelined.HRB:
          is_data_in = False

        if is_data_in:
          # Raise PiloDataIn event so that objects above us know a message has come in
          log.debug('Raising PiloDataIn. payload=')
          log.debug(binascii.hexlify(pipelined.payload))
          # TODO: Need to sort out whether we need to raise on one or both
          self.transport.raiseEvent(PiloDataIn, pipelined.payload)
          self.raiseEvent(PiloDataIn, pipelined.payload)

        if pipelined in self.rx_buffer:
          self.rx_buffer.remove(pipelined)

    # If this packet does not match the sender's rx_seq
    else:
      log.debug('Does not match rx_seq')
      log.debug('rx_seq = ' + str(self.rx_seq))
      log.debug(packet)
      # if it's above current rx_seq
      if packet.seq > self.rx_seq:
        # add this packet to the rx_buffer
        already_buffered = False
        for buffered in self.rx_buffer:
          if buffered == packet:
            already_buffered = True

        if not already_buffered:
          self.rx_buffer.append(packet)

        # ack the current rx_seq
        if self.most_recent_rx:
          self.ack(self.most_recent_rx)

      else:
        # if it's below the current rx_seq we've already received it and we should ack this anyway
        # TODO: this is getting called too many times - gotta figure out a way to clamp down at the very least
        # self.ack(packet)
        pass

  def handle_heartbeat_in (self, hrb_packet):
    if hrb_packet.seq == (self.rx_hrb_seq):
      self.rx_hrb_seq += 1
      self.ack(hrb_packet, HRB=True)


  def handle_ack_in (self, ack_packet):

    if not ack_packet.ACK:
      # if for some reason we get a packet here that isn't an ack, return
      return

    log.debug('Handling ack:')
    log.debug(ack_packet)

    # If acked, remove from in_transit and callback
    # if ack_packet.ack <= self.tx_seq, resend
    # for every packet in partial_acks

    acked = False
    to_remove = []
    for seq, sent in self.in_transit.iteritems():
      packet = sent['packet']
      packet_acked = False

      if (ack_packet.seq >= packet.seq and
          ack_packet.ack >= packet.seq + 1 and
          ack_packet.HRB == packet.HRB):

        packet_acked = True
        acked = True

      if ack_packet.partial_acks:
        for p_ack in ack_packet.get_partial_acks():
          if (ack_packet.seq >= packet.seq and
              ack_packet.ack >= packet.seq + 1 and
              not packet.HRB):

            packet_acked = True

      if packet_acked:
        log.debug('Received ACK for packet:')
        log.debug(packet)
        log.debug('\n')

        to_remove.append(sent)

    if to_remove:
      self.remove_from_transit(to_remove)
    else:
      try:
        self.send_packet(self.in_transit[ack_packet.ack - 1]['packet'])
      except KeyError:
        log.debug('Packet already removed')

    if ack_packet.partial_acks:
      for ack_hole in ack_packet.get_partial_ack_holes():
        self.send_packet(self.in_transit[ack_hole - 1]['packet'])

  def remove_from_transit (self, sent_array):
    for sent in sent_array:
      remove_seq = None
      for seq, value in self.in_transit.iteritems():
        if sent['packet'] == value['packet']:
          packet = sent['packet']
          remove_seq = seq
          log.debug('calling ack callback for packet' + str(packet))
          if sent['callback']:
            sent['callback'](packet)

      if remove_seq is not None:
        log.debug('removing sent item with seq = ' + str(remove_seq))
        self.in_transit.pop(remove_seq)

  def send (self, msg=None, callback=None, seq=None, **flags):
    packet = pkt.pilo()
    packet.src_address  = self.config.src_address
    packet.dst_address  = self.dst_address

    # TODO: there has got to be a better way to do this....
    try:
      if flags['ACK']:
        packet.ACK = True
    except KeyError:
      pass
    try:
      if flags['SYN']:
        packet.SYN = True
    except KeyError:
      pass
    try:
      if flags['FIN']:
        packet.FIN = True
    except KeyError:
      pass
    try:
      if flags['HRB']:
        packet.HRB = True
    except KeyError:
      pass

    if msg:
      packet.payload = msg

    if packet.HRB:
      packet.seq = self.tx_hrb_seq
      self.tx_hrb_seq += 1
    else:
      packet.seq = self.tx_seq
      self.tx_seq += 1

    self.send_packet(packet, callback=callback)

  def send_packet (self, packet, callback=None):

    log.debug('send_packet')
    log.debug(packet)

    already_queued = False
    # Don't queue/send identical packets
    for seq, transit in self.in_transit.iteritems():
      if transit['packet'] == packet:
        already_queued = True

    self.transport.send_pilo_broadcast(packet)

    if not already_queued:
      index_val = packet.seq
      if packet.HRB:
        index_val = str(index_val) + 'HRB'
      self.in_transit[index_val] = {
        'packet':packet,
        'callback': callback
        }
      self.ack_timers.append(Timer(self.config.retransmission_timeout, self.check_acked, args=[packet]))


  def check_acked(self, pilo_packet):
    log.debug('checking if acked:')
    log.debug(pilo_packet)
    still_in_transit = False

    for seq, sent in self.in_transit.iteritems():
      packet = sent['packet']
      if packet == pilo_packet:
        still_in_transit = True

    log.debug(pilo_packet)
    if still_in_transit:
      log.debug('is still in transit')
      self.transport.send_pilo_broadcast(pilo_packet)
      self.ack_timers.append(Timer(self.config.retransmission_timeout, self.check_acked, args=[pilo_packet]))

    else:
      log.debug('is not still in transit')

  def check_heartbeat (self):
    def _heartbeat_acked (packet):
      self.expiration_timer.cancel()
      self.heartbeat_timer = Timer(self.config.heartbeat_interval, self.check_heartbeat)

    self.send(callback=_heartbeat_acked, HRB=True)
    self.expiration_timer = Timer(self.config.heartbeat_interval, self.heartbeat_timeout)

  def heartbeat_timeout (self):
    log.debug('heartbeat timeout for connection: ' + str(self))
    # TODO: best way to signal connection down here?
    # No need to do any FIN/FINACK I think...
    self.connected = False
    self.transport.raiseEvent(PiloConnectionDown, self)
    self.cleanup()

  def cleanup (self):
    self.heartbeat_timer.cancel()
    self.expiration_timer.cancel()
    for ack_timer in self.ack_timers:
      ack_timer.cancel()


