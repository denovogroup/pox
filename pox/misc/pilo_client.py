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

    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def broadcast_ovs_message(self, packet):
    """
    This function will broadcast the message we've received from ovs.
    We need to create a PILO header to wrap whatever we've received from OVS
    """
    log.debug("sending broadcast packet")
    log.debug(packet)

    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = pkt.packet_utils.mac_string_to_addr(get_hw_addr('br-int'))
    pilo_packet.dst_address  = pkt.packet_utils.mac_string_to_addr(TMP_CONTROLLER_MAC)
    pilo_packet.seq = 0
    pilo_packet.ack = 0
    pilo_packet.flags = 0
    pilo_packet.payload = packet

    packed = pilo_packet.pack()

    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(packed, (UDP_IP, UDP_PORT))

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
    local_mac = get_hw_addr('br-int') #TODO: get interface from parameters? or maybe OVS?

    log.debug('eth src = ' + str(eth.src))
    log.debug('local mac = ' + str(local_mac))
    if str(eth.src) == str(local_mac):
      return

    try:
      udp = packet.find('udp')
    except Exception as e:
      log.debug('Can\'t find udp packet')
      log.debug(e)
      return

    pilo_packet = pkt.pilo(udp.payload)
    log.debug('PILO packet: ' + str(pilo_packet))

    of_packet = pilo_packet.payload
    log.debug('OF packet: ' + str(of_packet))


    self.connection.send(of_packet)
    # self.broadcast_ovs_message(packet.pack())


"""
PILO Broadcast specific
"""

class BroadcastHandler(DatagramProtocol):

  def datagramReceived(self, data, (host, port)):
    log.debug("received %r from %s:%d" % (data, host, port))

    log.debug("broadcast msg len = " + str(len(data)))
    broadcast_in = pkt.pilo.unpack(data)

    log.debug("broadcast msg src = " + str(broadcast_in.src_address))
    log.debug(str(broadcast_in))

def launch ():
  """
  Starts the component
  """

  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    PiloClient(event.connection)

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


  thread = Thread(target=run)
  thread.daemon = True
  thread.start()

  core.openflow.addListenerByName("ConnectionUp", start_switch)

