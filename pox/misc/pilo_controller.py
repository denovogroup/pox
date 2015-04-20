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
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from threading import Thread
from lib.util import get_hw_addr, get_ip_address
import socket, struct
import traceback
import json

log = core.getLogger()

class BroadcastHandler(DatagramProtocol):

  def datagramReceived(self, data, (host, port)):
    global controller
    log.debug("received %r from %s:%d" % (data, host, port))

    try:
      broadcast_in = pkt.pilo.unpack(data)
    except Exception as e:
      log.debug(e)
      log.debug('Can\'t parse as PILO packet')
      return

    log.debug('PILO Packet:')
    log.debug(broadcast_in)

    if pkt.packet_utils.same_mac(pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF)), broadcast_in.src_address):
      log.debug('This came from us, so we can ignore')
      return

    if broadcast_in.ACK:
      if broadcast_in.SYN:
        already_controlling = False
        for controlled in controller.controlling:
          if pkt.packet_utils.same_mac(controlled['mac'], broadcast_in.src_address):
            already_controlling = True

        if not already_controlling:
          # This means that we've established a connection with the client
          log.debug('Controlling: ' + str(broadcast_in.src_address))
          controller.controlling.append({
                'mac_to_port': {},
                'mac': EthAddr(broadcast_in.src_address)
              })
          controller.sender.send_synack(broadcast_in)

      controller.sender.handle_ack(broadcast_in)

    else:
      # This is an OVS PILO query - we *should* be able to handle it like a normal packet_in
      log.debug(broadcast_in)

      def handle_pilo_message(broadcast_in):
        try:
          inner_packet = of.ofp_packet_in()
          log.debug('attempting to unpack payload from:')
          log.debug(broadcast_in)
          inner_packet.unpack(broadcast_in.payload)
          log.debug('ofp_packet_in packet:')
          # log.debug(inner_packet)
          ethernet_packet = pkt.ethernet(inner_packet.data)
          log.debug('ethernet packet:')
          log.debug(ethernet_packet)

          for client in controller.controlling:
            if broadcast_in.src_address == client['mac']:
              log.debug('This PILO packet matches our client:')
              log.debug(client)
              pilo_client = client

              # TODO: This is where we would send back OF messages to switch

        except Exception:
          log.debug(traceback.format_exc())

      controller.receiver.handle_packet_in(broadcast_in, handle_pilo_message)

class PiloController:
  """
  A PiloController object will be created once at the startup of POX
  """
  def __init__ (self, clients, sender, receiver):
    self.unacked = []
    self.controlling = []
    self.sender = sender
    self.receiver = receiver

    for client in clients:
      self.sender.send_syn(client)

  def send_control_msg(self, client, msg):
    # Takes an of message and sends it to client via PILO

    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
    pilo_packet.dst_address  = client['mac']
    pilo_packet.payload = msg.pack()

    log.debug("sending broadcast packet:")
    log.debug(pilo_packet)

    self.sender.send(pilo_packet)


def launch (udp_ip, udp_port, this_if, tmp_dst_mac, retransmission_timeout="5"):
  """
  Starts the pilo_controller component
  """

  global UDP_IP
  global UDP_PORT
  global THIS_IF
  global THIS_IP
  global TMP_DST_MAC
  global controller

  UDP_IP = udp_ip
  UDP_PORT = int(udp_port)
  THIS_IF = this_if
  THIS_IP = get_ip_address(THIS_IF)
  TMP_DST_MAC = tmp_dst_mac # server1 vagrant
  src_ip = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
  src_address = get_hw_addr(THIS_IF)

  def run ():
    try:

      sock = socket.socket(socket.AF_INET, # Internet
          socket.SOCK_DGRAM) # UDP
      sock.bind(('', UDP_PORT))
      sock.setblocking(False)

      port = reactor.adoptDatagramPort(
          sock.fileno(), socket.AF_INET, BroadcastHandler(), maxPacketSize=65507)

      sock.close()

      log.debug("Listening on %s:%d" % (UDP_IP, UDP_PORT))

      reactor.run(installSignalHandlers=0)

    except Exception:
      print traceback.format_exc()

  # TODO: Take this in from command line!
  clients = [TMP_DST_MAC]

  sender = PiloSender(UDP_IP, UDP_PORT, int(retransmission_timeout), src_address)
  receiver = PiloReceiver(src_ip, UDP_IP, UDP_PORT)
  controller = PiloController(clients, sender, receiver)

  thread = Thread(target=run)
  thread.daemon = True
  thread.start()

