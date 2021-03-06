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
This is a very dumb controller for pilo testing purposes
"""

from pox.lib.recoco import Timer
from pox.core import core
from pox.openflow.of_01 import ConnectionDown
import pox.openflow.libopenflow_01 as of
from pox.lib.revent.revent import EventMixin
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()



class TestController (object):
  def __init__ (self, connection):
    self.connected = True
    self.connection = connection
    self.counter = 0
    self.listeners = []

    log.debug('connection: ')
    log.debug(self.connection)
    self.listeners = connection.addListeners(self)

    def _send_random_flow ():
      if not self.connected:
        return False

      log.debug('-- Sending random flow --')
      # Creates an open flow rule which should send PILO broadcast messages
      # to our handler
      delete_msg = of.ofp_flow_mod()
      delete_msg.command = of.OFPFC_DELETE
      delete_msg.match.priority = self.counter
      delete_msg.match.dl_type = pkt.ethernet.IP_TYPE
      delete_msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
      delete_msg.match.nw_dst = IPAddr('100.100.100.100')
      self.connection.send(delete_msg)
      self.counter += 1

      random_flow = of.ofp_flow_mod()
      random_flow.priority = self.counter
      random_flow.match.dl_type = pkt.ethernet.IP_TYPE
      random_flow.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
      random_flow.match.nw_dst = IPAddr('100.100.100.100')
      random_flow.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))

      self.connection.send(random_flow)

    self.timer = Timer(10, _send_random_flow, recurring=True)
    _send_random_flow()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from a remote pilo switch.
    """
    log.debug(' -- Received Packet in in test controller -- \n\n')
    log.debug(event)

    packet = event.parsed # This is the parsed packet data.
    log.debug(packet)

    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    log.debug(packet_in)
    log.debug(' -- Received Packet in in test controller -- \n\n')

  def _handle_ConnectionDown (self, event):
    log.debug('test controller handle connection down')
    self.connected = False
    self.timer.cancel()
    self.connection.removeListeners(self.listeners)


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    TestController(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
