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
from pox.misc.pilo_transport import PiloSender, PiloReceiver

from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from threading import Thread
import socket, struct
import traceback
from lib.util import get_hw_addr

log = core.getLogger()

"""
Traditional POX code
"""

class PiloClient (object):
  """
  A Pilo object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection, sender, receiver):

    self.connection = connection
    self.sender = sender
    self.receiver = receiver

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


    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.controller_address = None
    self.has_controller = False

  def remove_controller(self, address):
    log.debug('self.has_controller = ' + str(self.has_controller))
    log.debug('self.controller_address = ' + str(self.controller_address))
    if self.has_controller and pkt.packet_utils.same_mac(address, self.controller_address):
      log.debug('Removing controller: ' + str(self.controller_address))
      self.has_controller = False
      self.controller_address = None

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

      dst_mac = EthAddr(pilo_packet.dst_address)
      src_mac = EthAddr(pilo_packet.src_address)

      if pkt.packet_utils.same_mac(local_mac, src_mac):
        log.debug('This came from us, so we can ignore')
        return

      if pkt.packet_utils.same_mac(dst_mac, local_mac):

        log.debug(pilo_packet)

        if pilo_packet.FIN and not pilo_packet.ACK:
          def fin_callback(finack_packet):
            # We've received an ACK from our FINACK and we should
            # check and reset our controller stats
            # finack_packet is the FINACK we sent
            log.debug('fin_callback')
            log.debug('finack_packet: ' + str(finack_packet))
            self.remove_controller(finack_packet.dst_address)
            self.receiver.fin_callback(pilo_packet, finack_packet)

          self.sender.handle_fin(pilo_packet, fin_callback)
          return

        if pilo_packet.SYN and pilo_packet.ACK:
          # This means that we might have a new controller
          if self.has_controller and self.controller_address and not pkt.packet_utils.same_mac(self.controller_address, src_mac):
            # We have a new controller and want to tell the previous controller know the connection is over
            self.sender.send_fin(self.controller_address)

          if not self.has_controller or not pkt.packet_utils.same_mac(self.controller_address, src_mac):
            self.controller_address = pilo_packet.src_address
            self.has_controller = True
            log.debug('We have a PILO controller with address:')
            log.debug(self.controller_address)

            def test_fin(packet):
              log.debug('sending fin')
              self.sender.send_fin(pilo_packet.src_address)

            # core.callDelayed(10, test_fin, pilo_packet)

        elif pilo_packet.SYN:
          # This is a controller attempting to establish a connection
          self.sender.send_synack(pilo_packet)

        elif pilo_packet.FIN and pilo_packet.ACK:
          log.debug('finack_packet: ' + str(pilo_packet))
          def finack_callback(packet):
            self.remove_controller(pilo_packet.src_address)

          self.receiver.handle_packet_in(pilo_packet, finack_callback)
          self.sender.handle_ack(pilo_packet)

        elif pilo_packet.ACK:
          # Handle ack reception
          self.sender.handle_ack(pilo_packet)

        elif self.has_controller and pkt.packet_utils.same_mac(pilo_packet.src_address, self.controller_address):

          # This sends the openflow rule to our OVS instance
          def of_to_ovs(pilo_packet):
            of_packet_raw = pilo_packet.payload
            self.connection.send(of_packet_raw)


          # Now we want to send/broadcast an ack
          self.receiver.handle_packet_in(pilo_packet, of_to_ovs)

        else:
          log.debug('This looks like an OF message that hasn\'t come from our controller:')
          log.debug(pilo_packet)

      else:
        log.debug('Message not for us, let\'s flood it back out')
        pilo_packet.ttl = pilo_packet.ttl - 1
        if pilo_packet.ttl > 0:
          self.sender.send_pilo_broadcast(pilo_packet)
        else:
          log.debug('TTL expired:')
          log.debug(pilo_packet)

    except Exception as e:
      log.debug(e)
      log.debug('Can\'t parse PILO packet - this is a packet that ovs doesn\'t know what to do with')

      try:
        log.debug('Attempting to get "packet_in"')
        packet_in = event.ofp # The actual ofp_packet_in message.
        # log.debug('packet_in:')
        # log.debug(packet_in)

        # We should send this to the controller to see what it would do with it
        if self.has_controller:
          pilo_packet = pkt.pilo()
          pilo_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
          pilo_packet.dst_address  = EthAddr(self.controller_address)
          pilo_packet.payload = packet_in.pack()

          log.debug('sending pilo ovs query to controller:')
          log.debug(pilo_packet)

          def pilo_packet_received(packet):
            log.debug('packet was acked by receiver:')
            log.debug(packet)

          self.sender.send(pilo_packet)

      except Exception as e:
        log.debug(e)

def launch (udp_ip, this_if, udp_port, controller_mac, retransmission_timeout="5"):
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
    sender = PiloSender(UDP_IP, UDP_PORT, int(retransmission_timeout), src_address)
    receiver = PiloReceiver(src_ip, UDP_IP, UDP_PORT)

    log.debug("Controlling %s" % (event.connection,))
    PiloClient(event.connection, sender, receiver)

  core.openflow.addListenerByName("ConnectionUp", start_switch)

