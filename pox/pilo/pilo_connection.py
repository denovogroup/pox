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
import binascii

log = core.getLogger()

unpackers = make_type_to_unpacker_table()

def pilo_handle_FEATURES_REPLY (con, msg):
  connecting = con.connect_time == None
  con.features = msg
  con.original_ports._ports = set(msg.ports)
  con.ports._reset()
  con.dpid = msg.datapath_id

  if not connecting:
    con.ofnexus._connect(con)
    e = con.ofnexus.raiseEventNoErrors(FeaturesReceived, con, msg)
    if e is None or e.halt != True:
      log.debug('\n\n--- Raising features received --- \n\n')
      con.raiseEventNoErrors(FeaturesReceived, con, msg)
    return

  nexus = core.OpenFlowConnectionArbiter.getNexus(con)
  if nexus is None:
    # Cancel connection
    con.info("No OpenFlow nexus for " +
             pox.lib.util.dpidToStr(msg.datapath_id))
    con.disconnect()
    return
  con.ofnexus = nexus
  con.ofnexus._connect(con)
  #connections[con.dpid] = con

  barrier = of.ofp_barrier_request()

  listeners = []

  def finish_connecting (event):
    log.debug('--- received BarrierIn in PiloConnection --- ')
    if event.xid != barrier.xid:
      log.debug('event.xid does not match barrier.xid')
      # con.dpid = None
      # con.err("failed connect")
      # con.disconnect()
    else:
      con.info("connected")
      con.connect_time = time.time()
      e = con.ofnexus.raiseEventNoErrors(ConnectionUp, con, msg)
      if e is None or e.halt != True:
        con.raiseEventNoErrors(ConnectionUp, con, msg)
      e = con.ofnexus.raiseEventNoErrors(FeaturesReceived, con, msg)
      if e is None or e.halt != True:
        con.raiseEventNoErrors(FeaturesReceived, con, msg)
    con.removeListeners(listeners)
  listeners.append(con.addListener(BarrierIn, finish_connecting))

  def also_finish_connecting (event):
    if event.xid != barrier.xid: return
    if event.ofp.type != of.OFPET_BAD_REQUEST: return
    if event.ofp.code != of.OFPBRC_BAD_TYPE: return
    # Okay, so this is probably an HP switch that doesn't support barriers
    # (ugh).  We'll just assume that things are okay.
    finish_connecting(event)
  listeners.append(con.addListener(ErrorIn, also_finish_connecting))

  #TODO: Add a timeout for finish_connecting

  if con.ofnexus.miss_send_len is not None:
    con.send(of.ofp_set_config(miss_send_len =
                                  con.ofnexus.miss_send_len))

  log.debug('sending barrier: ')
  log.debug(barrier)
  con.send(barrier)

# TODO: If we want to dig into pox/of core more, we can refactor this to make cleaner
# We can override message handlers here
handlerMap[of.OFPT_FEATURES_REPLY] =  pilo_handle_FEATURES_REPLY
handlers = set_handlers(handlerMap)


class PiloConnection (Connection):
  """
  A Pilo Connection represents a pilo tunneled session
  with an openflow switch
  """

  def __init__ (self, sock, pilo_connection):

    self.pilo_connection = pilo_connection
    self.dpid = EthAddr(pilo_connection.dst_address)
    self.pilo_connection = pilo_connection
    self.pilo_connection.addListenerByName('PiloDataIn', self.receive)

    super(PiloConnection, self).__init__(sock, send_hello=False)

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

    self.pilo_connection.close(callback=disconnect_callback)

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

    log.debug('sending to switch from piloconnection')
    log.debug('msg=')
    log.debug(binascii.hexlify(data))
    self.pilo_connection.send(msg=data)

  def receive (self, event):
    """
    This should be called from PiloTransportConnection with a message that's ready to be handled
    It should contain the payload of a PILO packet which *should* be an OF message
    It doesn't currently implement any sort of buffering, so it will receive single
    PILO payloads and send them to any handlers as such
    TODO: maxb - this is a little too copy+pasted frome of connection. Need to go back through.
    """

    msg = event.msg
    offset = 0
    ofp_type = ord(msg[offset+1])
    log.debug('ofp_type = ' + str(ofp_type))

    log.debug('ofp_version = ' + str(ord(msg[offset])))

    if ord(msg[offset]) != of.OFP_VERSION:
      if ofp_type == of.OFPT_HELLO:
        # We let this through and hope the other side switches down.
        pass
      else:
        log.warning("Bad OpenFlow version (0x%02x) on connection %s"
                    % (ord(msg[offset]), self))
        self.close()

    msg_length = ord(msg[offset+2]) << 8 | ord(msg[offset+3])

    new_offset,msg = unpackers[ofp_type](msg, offset)
    assert new_offset - offset == msg_length

    log.debug('Receiving in pilo_connection:')
    log.debug(msg)

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


