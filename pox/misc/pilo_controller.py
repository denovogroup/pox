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
from pox.misc.pilo_transport import PiloSender, PiloReceiver

from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from lib.util import get_hw_addr, get_ip_address
import traceback
import json

log = core.getLogger()

class PiloController:
  """
  A PiloController object will be created once at the startup of POX
  """
  def __init__ (self, connection, client_macs, sender, receiver):

    self.connection = connection
    self.unacked = []
    self.controlling = []
    self.sender = sender
    self.receiver = receiver

    for client_mac in client_macs:
      self.sender.send_syn(client_mac)

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
    normal_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))

    self.connection.send(normal_msg_flow)

    # A Final rule to send any ovs rule misses to the controller
    # I believe that OF 1.0 does this automatically, but later versions do not
    table_miss_msg_flow = of.ofp_flow_mod()
    table_miss_msg_flow.priority = 1
    table_miss_msg_flow.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

    self.connection.send(table_miss_msg_flow)


    # This binds our PacketIn event listener
    connection.addListeners(self)


  def send_control_msg(self, client, msg):
    # Takes an of message and sends it to client via PILO

    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
    pilo_packet.dst_address  = client['mac']
    pilo_packet.payload = msg.pack()

    log.debug("sending broadcast packet:")
    log.debug(pilo_packet)

    self.sender.send(pilo_packet)


  def remove_client(self, address):
    for controlled in self.controlling:
      if pkt.packet_utils.same_mac(controlled['mac'], address):
        log.debug('No longer controlling: ' + str(controlled))
        self.controlling.remove(controlled)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    broadcast_in = event.parsed # This is the parsed packet data.

    if not broadcast_in.parsed:
      log.warning("Ignoring incomplete packet")
      return

    log.debug("handle packet in: ")
    log.debug(broadcast_in)

    eth = broadcast_in.find('ethernet')
    local_mac = EthAddr(get_hw_addr(THIS_IF))

    if pkt.packet_utils.same_mac(eth.src, local_mac):
      log.debug('This is a packet from this switch!')
      return

    # Ignore ARP requests because the arp-responder module is doing this
    a = broadcast_in.find('arp')
    if a:
      log.debug('This is an ARP request, so pilo_controller is gonna ignore it')
      return

    try:
      udp = broadcast_in.find('udp')

      pilo_packet = pkt.pilo(udp.payload)

      log.debug('PILO packet: ' + str(pilo_packet))

      dst_mac = EthAddr(pilo_packet.dst_address)
      src_mac = EthAddr(pilo_packet.src_address)

      if pkt.packet_utils.same_mac(local_mac, src_mac):
        log.debug('This came from us, so we can ignore')
        return

      if not pkt.packet_utils.same_mac(dst_mac, local_mac):
        log.debug('This PILO packet is not destined for us')
        return

      if pilo_packet.FIN and not pilo_packet.ACK:
        def fin_callback(finack_packet):
          # We've received an ACK from our FINACK and we should
          # check and reset our controller stats
          # finack_packet is the FINACK we sent
          log.debug('fin_callback')
          log.debug('finack_packet: ' + str(finack_packet))
          self.remove_client(finack_packet.dst_address)
          self.receiver.fin_callback(pilo_packet, finack_packet)

        self.sender.handle_fin(pilo_packet, fin_callback)
        return

      if pilo_packet.ACK:
        if pilo_packet.SYN:
          already_controlling = False
          for controlled in self.controlling:
            if pkt.packet_utils.same_mac(controlled['mac'], pilo_packet.src_address):
              already_controlling = True

          if not already_controlling:
            # This means that we've established a connection with the client
            log.debug('Controlling: ' + str(pilo_packet.src_address))
            self.controlling.append({
                  'mac_to_port': {},
                  'mac': EthAddr(pilo_packet.src_address)
                })
            self.sender.send_synack(pilo_packet)


        elif pilo_packet.FIN:
          def finack_callback(packet):
            log.debug('finack_packet: ' + str(pilo_packet))
            self.remove_client(pilo_packet.src_address)

          self.receiver.handle_packet_in(pilo_packet, finack_callback)

        self.sender.handle_ack(pilo_packet)

      else:
        # This is an OVS PILO query - we *should* be able to handle it like a normal packet_in
        log.debug(pilo_packet)

        def handle_pilo_message(pilo_packet):
          try:
            inner_packet = of.ofp_packet_in()
            log.debug('attempting to unpack payload from:')
            log.debug(pilo_packet)
            inner_packet.unpack(pilo_packet.payload)
            log.debug('ofp_packet_in packet:')
            # log.debug(inner_packet)
            ethernet_packet = pkt.ethernet(inner_packet.data)
            log.debug('ethernet packet:')
            log.debug(ethernet_packet)

            for client in self.controlling:
              if pilo_packet.src_address == client['mac']:
                log.debug('This PILO packet matches our client:')
                log.debug(client)
                pilo_client = client

                # TODO: This is where we would send back OF messages to switch

          except Exception:
            log.debug(traceback.format_exc())

        log.debug('handle packet in:')
        log.debug(pilo_packet)
        self.receiver.handle_packet_in(pilo_packet, handle_pilo_message)

    except Exception as e:
      log.debug(e)
      log.debug('Can\'t parse as PILO packet')
      return


def launch (udp_ip, udp_port, this_if, client_macs, retransmission_timeout="5"):
  """
  Starts the pilo_controller component
  """

  global UDP_IP
  global UDP_PORT
  global THIS_IF
  global THIS_IP
  global controller

  UDP_IP = udp_ip
  UDP_PORT = int(udp_port)
  THIS_IF = this_if
  THIS_IP = get_ip_address(THIS_IF)
  src_ip = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
  src_address = get_hw_addr(THIS_IF)
  client_macs = client_macs.split(',')

  sender = PiloSender(UDP_IP, UDP_PORT, int(retransmission_timeout), src_address)
  receiver = PiloReceiver(src_ip, UDP_IP, UDP_PORT)

  def start_switch (event):
    sender = PiloSender(UDP_IP, UDP_PORT, int(retransmission_timeout), src_address)
    receiver = PiloReceiver(src_ip, UDP_IP, UDP_PORT)

    log.debug("Controlling %s" % (event.connection,))
    PiloController(event.connection, client_macs, sender, receiver)

  core.openflow.addListenerByName("ConnectionUp", start_switch)

