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
import pox.lib.packet as pkt
from pox.pilo.pilo_transport import PiloTransport, PiloPacketIn
from pox.pilo.pilo_connection import PiloConnection
from pox.lib.revent.revent import EventMixin
from pox.lib.revent import EventHalt
from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from lib.util import get_hw_addr, get_ip_address
import traceback
import json
import binascii

log = core.getLogger()

class PiloController (EventMixin):
  _eventMixin_events = set([PiloPacketIn])
  """
  A PiloController object will be created once at the startup of POX
  """
  def __init__ (self, connection, client_macs):

    self.connection = connection
    self.unacked = []
    self.controlling = []

    self.transport = PiloTransport(self, UDP_IP, UDP_PORT, SRC_IP, SRC_ADDRESS, RETRANSMISSION_TIMEOUT, HEARTBEAT_INTERVAL)

    for client_mac in client_macs:
      self.transport.initiate_connection(client_mac)

    # Creates an open flow rule which should send PILO broadcast messages
    # to our handler
    broadcast_msg_flow = of.ofp_flow_mod()
    broadcast_msg_flow.priority = 100
    broadcast_msg_flow.match.dl_type = pkt.ethernet.IP_TYPE
    broadcast_msg_flow.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    broadcast_msg_flow.match.nw_dst = IPAddr(UDP_IP) # TODO: better matching for broadcast IP
    broadcast_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

    self.connection.send(broadcast_msg_flow)

    normal_msg_flow = of.ofp_flow_mod()
    normal_msg_flow.priority = 101
    normal_msg_flow.match.dl_type = pkt.ethernet.IP_TYPE
    normal_msg_flow.match.dl_src = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
    normal_msg_flow.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    normal_msg_flow.match.nw_dst = IPAddr(UDP_IP) # TODO: better matching for broadcast IP
    normal_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_ALL))

    self.connection.send(normal_msg_flow)

    # A Final rule to send any ovs rule misses to the controller
    # I believe that OF 1.0 does this automatically, but later versions do not
    table_miss_msg_flow = of.ofp_flow_mod()
    table_miss_msg_flow.priority = 1
    table_miss_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

    self.connection.send(table_miss_msg_flow)

    connection.addListeners(self)
    self.transport.addListeners(self)

  # TODO: Need to raise ConnectionDown event here
  def remove_client(self, address):
    for controlled in self.controlling:
      if pkt.packet_utils.same_mac(controlled['mac'], address):
        log.debug('No longer controlling: ' + str(controlled))
        self.controlling.remove(controlled)

  def _handle_ConnectionDown (self, event):
    """
    This was happening when we were getting socket errors attempting to
    talk to the pilo controller ovs instance
    TODO: is this the appropriate place to deal with it?
    """
    for controlled in self.controlling:
      self.transport.terminate_connection(controlled['mac'])

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
      newcon = PiloConnection(self.connection.sock, event.connection)
      self.controlling.append({
            'mac': EthAddr(client_address)
          })

      self.pilo_connection = event.connection
      self.pilo_connection.addListeners(self)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    log.debug("handle packet in: ")
    log.debug(packet)

    eth = packet.find('ethernet')
    local_mac = EthAddr(get_hw_addr(THIS_IF))

    if pkt.packet_utils.same_mac(eth.src, local_mac):
      log.debug('This is a packet from this switch!')
      return

    # Ignore ARP requests because the arp-responder module is doing this
    a = packet.find('arp')
    if a:
      log.debug('This is an ARP request, so pilo_controller is gonna ignore it')
      return

    try:
      udp = packet.find('udp')

      pilo_packet = pkt.pilo(udp.payload)

      log.debug('PILO packet: ' + str(pilo_packet))
      self.raiseEvent(PiloPacketIn, pilo_packet, event.ofp, packet)

    except Exception as e:
      log.debug(e)
      log.debug('Can\'t parse as PILO:')
      log.debug(packet)


def launch (udp_ip, udp_port, this_if, client_macs, retransmission_timeout="5", heartbeat_interval="10"):
  """
  Starts the pilo_controller component
  """

  global UDP_IP
  global UDP_PORT
  global THIS_IF
  global THIS_IP
  global controller
  global RETRANSMISSION_TIMEOUT
  global HEARTBEAT_INTERVAL
  global SRC_IP
  global SRC_ADDRESS

  UDP_IP = udp_ip
  UDP_PORT = int(udp_port)
  THIS_IF = this_if
  THIS_IP = get_ip_address(THIS_IF)
  # TODO: This SRC_IP assignment is COMPLETELY WRONG
  SRC_IP = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
  SRC_ADDRESS = get_hw_addr(THIS_IF)
  HEARTBEAT_INTERVAL = int(heartbeat_interval)
  RETRANSMISSION_TIMEOUT = int(retransmission_timeout)

  client_macs = client_macs.split(',')

  def start_switch (event):
    new_connection = event.connection
    if isinstance(new_connection, PiloConnection):
      return

    log.debug("Controlling %s" % (event.connection,))
    PiloController(event.connection, client_macs)
    return EventHalt

  core.openflow.addListenerByName("ConnectionUp", start_switch, priority=9) # Arbitrary priority needs to be >0

