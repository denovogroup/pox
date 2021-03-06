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
This component will implement the PILO (physically in band logically out of band) controller part of SDN openflow.

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.of_01 import ConnectionDown
import pox.lib.packet as pkt
from pox.pilo.pilo_transport import PiloTransport, PiloPacketIn
from pox.pilo.pilo_connection import PiloConnection
from pox.lib.revent.revent import EventMixin
from pox.lib.revent import Event, EventHalt
from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.util import get_hw_addr, get_ip_address
import traceback
import json
import binascii

log = core.getLogger()

class PiloController (EventMixin):
  _eventMixin_events = set([PiloPacketIn, ConnectionDown])
  """
  A PiloController object will be created once at the startup of POX
  """
  def __init__ (self, connection, client_macs, **kwargs):

    for name, value in kwargs.items():
      setattr(self, name, value)

    self.connection = connection
    self.unacked = []
    self.controlling = []

    self.transport = PiloTransport(self, self.udp_ip, self.udp_port, self.src_address, self.retransmission_timeout, self.heartbeat_interval)

    for client_mac in client_macs:
      self.transport.initiate_connection(client_mac)

    # Creates an open flow rule which should send PILO broadcast messages
    # to our handler
    broadcast_msg_flow = of.ofp_flow_mod()
    broadcast_msg_flow.priority = 100
    broadcast_msg_flow.match.dl_type = pkt.ethernet.IP_TYPE
    broadcast_msg_flow.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    broadcast_msg_flow.match.nw_dst = IPAddr(self.udp_ip) # TODO: better matching for broadcast IP
    broadcast_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

    self.connection.send(broadcast_msg_flow)

    normal_msg_flow = of.ofp_flow_mod()
    normal_msg_flow.priority = 101
    normal_msg_flow.match.dl_type = pkt.ethernet.IP_TYPE
    normal_msg_flow.match.dl_src = pkt.packet_utils.mac_string_to_addr(get_hw_addr(self.this_if))
    normal_msg_flow.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    normal_msg_flow.match.nw_dst = IPAddr(self.udp_ip) # TODO: better matching for broadcast IP
    normal_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_ALL))

    self.connection.send(normal_msg_flow)

    # A Final rule to send any ovs rule misses to the controller
    # I believe that OF 1.0 does this automatically, but later versions do not
    table_miss_msg_flow = of.ofp_flow_mod()
    table_miss_msg_flow.priority = 1
    table_miss_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

    self.connection.send(table_miss_msg_flow)

    connection.addListeners(self, priority=99)
    self.transport.addListeners(self)
    core.addListeners(self, priority=99)
    core.openflow.addListeners(self, priority=99)

  # TODO: Need to raise ConnectionDown event here
  def remove_client(self, address):
    for controlled in self.controlling:
      if pkt.packet_utils.same_mac(controlled['mac'], address):
        log.debug('No longer controlling: ' + str(controlled))
        self.controlling.remove(controlled)

    if self.retry_on_disconnect:
      log.debug('Attempting to re-initiate connection with Timer.')
      Timer(1, self.transport.initiate_connection, args=[address])


  def _handle_ConnectionDown (self, event):
    """
    This was happening when we were getting socket errors attempting to
    talk to the pilo controller ovs instance
    TODO: is this the appropriate place to deal with it?
    """
    for controlled in self.controlling:
      self.transport.terminate_connection(controlled['mac'])

    return EventHalt


  def _handle_PiloConnectionDown (self, event):
    client_address = event.dst_address
    self.remove_client(client_address)


  def _handle_PiloConnectionUp (self, event):
    log.debug('_handle_PiloConnectionUp: ' + str(event.dst_address))
    client_address = event.connection.dst_address
    already_controlling = False
    for controlled in self.controlling:
      if pkt.packet_utils.same_mac(controlled['mac'], client_address):
        already_controlling = True

    if not already_controlling:
      # This means that we've established a connection with the client
      log.debug('Controlling: ' + str(client_address))
      self.controlling.append({
            'mac': EthAddr(client_address),
            'connection': PiloConnection(self.connection.sock, event.connection)
          })


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    connection = event.connection
    if isinstance(connection, PiloConnection):
      log.debug('this is a piloConnection, so we\'ll return and let other listeners handle it')
      return

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    log.debug("handle packet in: ")
    log.debug(packet)

    eth = packet.find('ethernet')
    local_mac = EthAddr(get_hw_addr(self.this_if))

    if pkt.packet_utils.same_mac(eth.src, local_mac):
      log.debug('This is a packet from this switch!')
      return EventHalt

    # # Ignore ARP requests because the arp-responder module is doing this
    # a = packet.find('arp')
    # if a:
    #   log.debug('This is an ARP request, so pilo_controller is gonna ignore it')
    #   return

    try:
      udp = packet.find('udp')

      pilo_packet = pkt.pilo(udp.payload)

      log.debug('PILO packet: ' + str(pilo_packet))
      self.raiseEvent(PiloPacketIn, pilo_packet, event.ofp, packet)

    except Exception as e:
      log.debug(e)
      log.debug('Can\'t parse as PILO:')
      log.debug(packet)


    log.debug('cancelling packet handle')
    return EventHalt

def launch (udp_ip, udp_port, this_if, client_macs, retransmission_timeout="5", heartbeat_interval="30", retry_on_disconnect=True):
  """
  Starts the pilo_controller component
  """

  udp_port = int(udp_port)
  this_ip = get_ip_address(this_if)
  src_address = pkt.packet_utils.mac_string_to_addr(get_hw_addr(this_if))
  heartbeat_interval = int(heartbeat_interval)
  retry_on_disconnect = bool(retry_on_disconnect)
  retransmission_timeout = int(retransmission_timeout)

  client_macs = client_macs.split(',')

  def start_switch (event):
    new_connection = event.connection
    if isinstance(new_connection, PiloConnection):
      return

    log.debug("Controlling %s" % (event.connection,))
    PiloController(event.connection, client_macs, udp_ip=udp_ip, udp_port=udp_port, this_if=this_if, \
               retransmission_timeout=retransmission_timeout, heartbeat_interval=heartbeat_interval, src_address=src_address, retry_on_disconnect=retry_on_disconnect)

  core.openflow.addListenerByName("ConnectionUp", start_switch, priority=9) # Arbitrary priority needs to be >0

  from pox.forwarding.l3_learning import launch
  launch(fakeways='10.1.100.1, 10.1.100.2, 10.1.100.3')
