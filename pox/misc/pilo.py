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
This component will implement PILO (physically in band logically out of band) SDN openflow.

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from threading import Thread

log = core.getLogger()



class Pilo (object):
  """
  A Pilo object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):

    self.connection = connection

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


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    self.act_like_hub(packet, packet_in)
    #self.act_like_switch(packet, packet_in)


class TwistedHandler(DatagramProtocol):

    def datagramReceived(self, data, (host, port)):
        print "received %r from %s:%d" % (data, host, port)
        self.transport.write(data, (host, port))



def launch ():
  """
  Starts the component
  """

  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Pilo(event.connection)

  def run ():
    try:

      UDP_IP = "192.168.1.255"
      UDP_PORT = 5005

      port_socket = socket.socket(socket.AF_INET, # Internet
                           socket.SOCK_DGRAM) # UDP
      port_socket.bind(('', UDP_PORT))
      port_socket.setblocking(False)

      port = reactor.adoptDatagramPort(
              port_socket.fileno(), socket.AF_INET, TwistedHandler(), maxPacketSize=65507)

      port_socket.close()

      print "ip: " + UDP_IP
      print "port: " + str(UDP_PORT)
      log.debug("Listening on %s:%d" % (UDP_IP, UDP_PORT))

      reactor.run(installSignalHandlers=0)

    except Exception:
      print traceback.format_exc()


  thread = Thread(target=run)
  thread.daemon = True
  thread.start()

  core.openflow.addListenerByName("ConnectionUp", start_switch)

