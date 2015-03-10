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

from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from threading import Thread
import socket, struct
import traceback
from lib.util import get_hw_addr

log = core.getLogger()

UDP_IP = "192.168.1.255"
THIS_IF = 'br-int'
UDP_PORT = 5005
TMP_CONTROLLER_MAC = '08:00:27:28:fa:9c'


"""
Traditional POX code
"""

class PiloClient (object):
  """
  A Pilo object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    global client

    self.connection = connection

    # Creates an open flow rule which should send PILO broadcast messages
    # to our handler
    broadcast_msg_flow = of.ofp_flow_mod()
    broadcast_msg_flow.priority = 101
    broadcast_msg_flow.match.dl_type = pkt.ethernet.IP_TYPE
    broadcast_msg_flow.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    broadcast_msg_flow.match.nw_dst = IPAddr(UDP_IP) # TODO: better matching for broadcast IP
    broadcast_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

    self.connection.send(broadcast_msg_flow)

    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.unacked = []
    self.controller_address = 0
    self.has_controller = False


  def broadcast_ovs_message(self, packet):
    """
    This function will broadcast the message we've received from ovs.
    We need to create a PILO header to wrap whatever we've received from OVS
    """
    log.debug("sending broadcast packet")

    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
    pilo_packet.dst_address  = pkt.packet_utils.mac_string_to_addr(TMP_CONTROLLER_MAC)
    pilo_packet.seq = 0
    pilo_packet.ack = 0
    pilo_packet.flags = 0
    pilo_packet.payload = packet

    self.send_pilo_broadcast(pilo_packet)

    self.unacked.append(pilo_packet)
    core.callDelayed(2, self.check_acked, pilo_packet)


  def send_pilo_broadcast(self, pilo_packet):
    packed = pilo_packet.pack()

    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(packed, (UDP_IP, UDP_PORT))


  def check_acked(self, pilo_packet):
    if pilo_packet in self.unacked:
      self.send_pilo_broadcast(pilo_packet)
      core.callDelayed(2, self.check_acked, pilo_packet)


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
    local_mac = EthAddr(get_hw_addr(THIS_IF)) #TODO: get interface from parameters? or maybe OVS?

    if pkt.packet_utils.same_mac(eth.src, local_mac):
      log.debug('This is a packet from this switch!')
      return

    try:
      udp = packet.find('udp')
    except Exception as e:
      log.debug('Can\'t find udp packet')
      log.debug(e)
      return

    try:
      pilo_packet = pkt.pilo(udp.payload)
      log.debug('PILO packet: ' + str(pilo_packet))
    except Exception as e:
      log.debug('Can\'t parse PILO packet')
      log.debug(e)
      return

    of_packet_raw = pilo_packet.payload
    # TODO: Would be nice to unpack the of_packet in order to read any of the insides
    # but I can't get it to work at the moment
    # of_packet = of.ofp_action_base(of_packet_raw)

    dst_mac = EthAddr(pilo_packet.dst_address)

    if pkt.packet_utils.same_mac(dst_mac, local_mac):

      log.debug(pilo_packet)
      if pilo_packet.SYN and pilo_packet.ACK:
        # This means that we now have a controller
        self.controller_address = pilo_packet.src_address
        self.has_controller = True

      elif pilo_packet.SYN:
        # This is a controller attempting to establish a connection
        self.send_synack(pilo_packet)

      elif self.has_controller and pkt.packet_utils.same_mac(pilo_packet.src_address, self.controller_address):
        # This sends the openflow rule to our OVS instance
        self.connection.send(of_packet_raw)

        # Now we want to send/broadcast an ack
        self.send_ack(pilo_packet)

      else:
        log.debug('This looks like an OF message that hasn\'t come from our controller:')
        log.debug(pilo_packet)

    else:
      log.debug('Message not for us, let\'s flood it back out')
      self.broadcast_ovs_message(packet.pack())


  def send_synack(self, pilo_packet):
    ack_seq = pilo_packet.seq + len(pilo_packet.raw)
    seq_no = pilo_packet.seq

    synack_packet = pkt.pilo()
    synack_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
    synack_packet.dst_address  = EthAddr(pilo_packet.src_address)
    synack_packet.seq = seq_no
    synack_packet.ack = ack_seq
    synack_packet.ACK = True
    synack_packet.SYN = True

    log.debug('sending synack')
    log.debug(synack_packet)

    self.send_pilo_broadcast(synack_packet)


  def send_ack(self, pilo_packet):
    ack_seq = pilo_packet.seq + len(pilo_packet.raw)
    seq_no = pilo_packet.seq

    ack_packet = pkt.pilo()
    ack_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
    ack_packet.dst_address  = EthAddr(pilo_packet.src_address)
    ack_packet.seq = seq_no
    ack_packet.ack = ack_seq
    ack_packet.ACK = True

    packed = ack_packet.pack()

    log.debug('sending ack')
    log.debug(ack_packet)

    self.send_pilo_broadcast(ack_packet)


def launch ():
  """
  Starts the component
  """

  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    PiloClient(event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_switch)

