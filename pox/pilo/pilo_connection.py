# Copyright 2015 Max Bittman Barath Raghavan, De Novo Group, et al
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
Pilo Connections extends the OF Connection class and provides some pilo-specific features;
handles some pilo-specific situations, etc.

"""
from pox.core import core
import pox
import pox.lib.util
from pox.openflow.of_01 import *
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr
from pox.lib.revent.revent import EventMixin
from pox.openflow.util import make_type_to_unpacker_table
import datetime
import time

log = core.getLogger()

unpackers = make_type_to_unpacker_table()

class PiloConnection (Connection):
  """
  A Pilo Connection represents a pilo tunneled session
  with an openflow switch
  """

  def __init__ (self, sock, pilo_address, sender, receiver):

    self.pilo_address = pilo_address
    self.dpid = EthAddr(pilo_address)
    self.transport.addListenerByName('PiloDataIn', self.receive)

    super(PiloConnection, self).__init__(sock)

  def close (self):
    self.disconnect('closed')

  def disconnect (self, msg = 'disconnected', defer_event = False):
    if self.disconnected:
      self.msg("already disconnected")
    self.info(msg)

    def disconnect_callback ():
      try:
        self.ofnexus._disconnect(self.dpid)
      except:
        pass
      if self.dpid is not None:
        if not self.disconnection_raised and not defer_event:
          self.disconnection_raised = True
          self.ofnexus.raiseEventNoErrors(ConnectionDown, self)
          self.raiseEventNoErrors(ConnectionDown, self)
      self.disconnected = True

    self.sender.disconnect(self.pilo_address, disconnect_callback)

  def send (self, data):
    """
    Send data to the switch over "pilo" tunnel.

    From Connection class:
    Data should probably either be raw bytes in OpenFlow wire format, or
    an OpenFlow controller-to-switch message object from libopenflow.
    """
    if self.disconnected: return
    if type(data) is not bytes:
      # There's actually no reason the data has to be an instance of
      # ofp_header, but this check is likely to catch a lot of bugs,
      # so we check it anyway.
      assert isinstance(data, of.ofp_header)
      data = data.pack()

    pilo_packet = pkt.pilo()
    pilo_packet.dst_address  = self.pilo_address
    pilo_packet.payload = data

    self.sender.send(pilo_packet)

  def receive (self, event):
    """
    This should be called from PiloTransport with a message that's ready to be handled
    It should contain the payload of a PILO packet which *should* be an OF message
    It doesn't currently implement any sort of buffering, so it will receive single
    PILO payloads and send them to any handlers as such
    """

    msg = event.msg
    offset = 0
    ofp_type = ord(msg[offset+1])

    if ord(self.buf[offset]) != of.OFP_VERSION:
      if ofp_type == of.OFPT_HELLO:
        # We let this through and hope the other side switches down.
        pass
      else:
        log.warning("Bad OpenFlow version (0x%02x) on connection %s"
                    % (ord(self.buf[offset]), self))
        self.close()

    msg_length = ord(self.buf[offset+2]) << 8 | ord(self.buf[offset+3])

    new_offset,msg = unpackers[ofp_type](self.buf, offset)
    assert new_offset - offset == msg_length

    try:
      handler = handlers[ofp_type]
      handler(self, msg)
    except:
      log.exception("%s: Exception while handling OpenFlow message:\n" +
                    "%s %s", self,self,
                    ("\n" + str(self) + " ").join(str(msg).split('\n')))
    return True


  def read (self):
    """
    read() should not get called for PiloConnection
    """
    raise RuntimeError("read() should not be called on a PiloConnection")

  def __str__ (self):
    #return "[Con " + str(self.ID) + "/" + str(self.dpid) + "]"
    if self.dpid is None:
      d = str(self.dpid)
    else:
      d = pox.lib.util.dpidToStr(self.dpid)
    return "[%s %i]" % (d, self.ID)


