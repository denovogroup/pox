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
This component will implement the PILO (physically in band logically out of band) client part of SDN openflow.

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.pilo.pilo_transport import PiloTransport

from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from threading import Thread
import socket, struct
import traceback
from lib.util import get_hw_addr

log = core.getLogger()


class PiloClient (EventMixin):
  _eventMixin_events = set([PiloPacketIn])
  """
  A Pilo object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection, transport):

    self.connection = connection
    self.transport = transport

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
    transport.addListeners(self)

    self.controller_address = None
    self.has_controller = False

  def remove_controller(self, address):
    log.debug('self.has_controller = ' + str(self.has_controller))
    log.debug('self.controller_address = ' + str(self.controller_address))
    if self.has_controller and pkt.packet_utils.same_mac(address, self.controller_address):
      log.debug('Removing controller: ' + str(self.controller_address))
      self.has_controller = False
      self.controller_address = None

  def _handle_PiloConnectionUp (self, event):
    controller_address = event.dst_address
    # This means that we might have a new controller
    if self.has_controller and self.controller_address and not pkt.packet_utils.same_mac(self.controller_address, controller_address):
      # We have a new controller and want to tell the previous controller know the connection is over
      self.transport.terminate_connection(self.controller_address)

    if not self.has_controller or not pkt.packet_utils.same_mac(self.controller_address, src_mac):
      self.controller_address = controller_address
      self.has_controller = True
      log.debug('We have a PILO controller with address:')
      log.debug(self.controller_address)

  def _handle_PiloConnectionDown (self, event):
    controller_address = event.dst_address
    self.remove_controller(controller_address)


  # We're going to need a handler for each of the connection events that we want to pass
  # to the PILO Controller:
  # handle_PACKET_IN,
  # handle_FEATURES_REPLY,
  # handle_PORT_STATUS,
  # handle_ERROR_MSG,
  # handle_BARRIER,
  # handle_STATS_REPLY,
  # handle_FLOW_REMOVED,
  # handle_VENDOR
  # These will never get raised to here:
  # handle_HELLO,
  # handle_ECHO_REQUEST,
  # handle_ECHO_REPLY,
  # see of_01.py lines 66-240 - all of these messages get handled there,
  # and all but the last three then get essentially re-raised on the connection EventMixin


  def _handle_FeaturesReceived (self, event):
    """
    Part of the inital non-pilo connection is a features request msg and then response from
    the client, so we "proxy" that message back to the controller here
    """
    self.proxy_message(event)

  def proxy_message (self, event):
    """
    Most of our _handle_ listeners are just going to proxy whatever message we get from the switch
    that we want to send to our controller so this can be a common function
    This is not appropriate for something like PacketIn, because those messages can be generated from
    actions that the switch itself takes
    """
    if self.has_controller and self.controller_address:
      log.debug('sending proxied OF message to controller:')
      log.debug(pilo_packet)

      self.transport.send(msg=event.ofp.pack(), dst_address=self.controller_address)

  def _handle_PiloDataIn (self, event):
    # This sends the PILO msg to our OVS instance
    msg = event.msg
    self.connection.send(msg)

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
      log.debug('This is an ARP request, so pilo_client is gonna ignore it')
      return

    try:
      udp = packet.find('udp')

      pilo_packet = pkt.pilo(udp.payload)

      log.debug('PILO packet: ' + str(pilo_packet))
      self.raiseEvent(PiloPacketIn, pilo_packet)

    except Exception as e:
      log.debug(e)
      log.debug('Can\'t parse PILO packet - this might be a table miss packet')

      try:
        log.debug('Attempting to get "packet_in"')
        packet_in = event.ofp # The actual openflow packet

        # We should send this to the controller to see what it would do with it
        if self.has_controller:
          log.debug('sending pilo ovs query to controller:')
          log.debug(pilo_packet)
          self.transport.send(self.controller_address, packet_in.pack())

      except Exception as e:
        log.debug(e)

def launch (udp_ip, this_if, udp_port, controller_mac, retransmission_timeout="5", heartbeat_interval="10"):
  """
  Starts the component
  """

  global UDP_IP
  global THIS_IF
  global UDP_PORT
  global CONTROLLER_MAC

  UDP_IP = udp_ip
  THIS_IF = this_if
  UDP_PORT = int(udp_port)
  CONTROLLER_MAC = controller_mac
  src_ip = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
  src_address = get_hw_addr(THIS_IF)

  def start_switch (event):
    pilo_transport = PiloTransport(self, UDP_IP, UDP_PORT, src_ip, src_address, int(retransmission_timeout), int(hearteat_interval))

    log.debug("Controlling %s" % (event.connection,))
    PiloClient(event.connection, pilo_transport)

  core.openflow.addListenerByName("ConnectionUp", start_switch)

