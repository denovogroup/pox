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

from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from threading import Thread
from lib.util import get_hw_addr, get_ip_address
import socket, struct
import traceback

log = core.getLogger()

ACK_TIMER = 5 # Amount of time to wait to resend
UDP_IP = "192.168.1.255"
UDP_PORT = 5005
THIS_IF = 'eth1'
THIS_IP = get_ip_address('eth1')
TMP_DST_MAC = "08:00:27:33:0b:f4" # server1 vagrant
# TMP_DST_MAC = "08:00:27:33:0b:f5" # random testing

class BroadcastHandler(DatagramProtocol):

  def datagramReceived(self, data, (host, port)):
    global controller
    log.debug("received %r from %s:%d" % (data, host, port))

    broadcast_in = pkt.pilo.unpack(data)
    if THIS_IP == host:
      log.debug('This came from us, so we can ignore')
      return

    if broadcast_in.ACK:
      if broadcast_in.SYN:
        # This means that we've established a connection with the client
        controller.controlling.append(EthAddr(broadcast_in.src_address))
        controller.send_synack(broadcast_in)

      for unacked in controller.unacked:
        log.debug(unacked)
        ack_len = unacked.seq + len(unacked.pack())

        if pkt.packet_utils.same_mac(unacked.dst_address, broadcast_in.src_address) and broadcast_in.ack == ack_len:

          log.debug('received ack:')
          log.debug(broadcast_in)

          log.debug('removing this packet:')
          log.debug(unacked)

          controller.unacked.remove(unacked)
          log.debug('any left in unacked?')
          for unack in controller.unacked:
            log.debug(unack)


class PiloController:
  """
  A PiloController object will be created once at the startup of POX
  """
  def __init__ (self):
    self.unacked = []
    self.controlling = []

  def take_control(self, dst):

    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
    pilo_packet.dst_address  = pkt.packet_utils.mac_string_to_addr(dst)
    pilo_packet.seq = 0
    pilo_packet.ack = 0
    pilo_packet.SYN = True

    log.debug("sending control packet")
    log.debug(pilo_packet)

    self.send_pilo_broadcast(pilo_packet)
    self.unacked.append(pilo_packet)
    core.callDelayed(ACK_TIMER, self.check_acked, pilo_packet)


  def send_control_msg(self):
    # Right now this is just an arbitrary message for testing
    # We'll probably want to take an OF action as a parameter

    new_flow = of.ofp_flow_mod()
    new_flow.priority = 9
    new_flow.match.dl_type = pkt.ethernet.IP_TYPE
    new_flow.match.nw_proto = pkt.ipv4.TCP_PROTOCOL
    new_flow.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

    for client_address in self.controlling:
      pilo_packet = pkt.pilo()
      pilo_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr(THIS_IF))
      pilo_packet.dst_address  = client_address
      pilo_packet.seq = 0
      pilo_packet.ack = 0
      pilo_packet.payload = new_flow.pack()

      log.debug("sending broadcast packet")
      log.debug(pilo_packet)

      self.send_pilo_broadcast(pilo_packet)
      self.unacked.append(pilo_packet)
      core.callDelayed(ACK_TIMER, self.check_acked, pilo_packet)


  def send_pilo_broadcast(self, pilo_packet):
    packed = pilo_packet.pack()

    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(packed, (UDP_IP, UDP_PORT))


  def check_acked(self, pilo_packet):
    if pilo_packet in self.unacked:
      log.debug('not acked')
      log.debug('resending unacked packet')
      self.send_pilo_broadcast(pilo_packet)
      core.callDelayed(ACK_TIMER, self.check_acked, pilo_packet)


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

    packed = synack_packet.pack()

    log.debug('sending synack')
    log.debug(synack_packet)

    self.send_pilo_broadcast(synack_packet)


def launch ():
  """
  Starts the pilo_controller component
  """
  global controller

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


  def check_control():
    if len(controller.controlling) > 0:
      controller.send_control_msg()
      return False

  controller = PiloController()
  controller.take_control(TMP_DST_MAC)

  Timer(3, check_control, recurring = True)

  thread = Thread(target=run)
  thread.daemon = True
  thread.start()

