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
Implements reliable transport for our PILO messages

"""

from pox.core import core
import pox.lib.packet as pkt

from pox.lib.recoco import Timer
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from twisted.internet.protocol import DatagramProtocol
from lib.util import get_hw_addr, get_ip_address
import socket, struct

log = core.getLogger()

class PiloTransport():
  def __init__ (self):
    log.debug('Creating PiloTransport object')

  def send_pilo_broadcast(self, packet):
    log.debug('Sending PILO broadcast')
    log.debug(packet)
    packed = packet.pack()

    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(packed, (self.udp_ip, self.udp_port))


class PiloSender(PiloTransport):
  def __init__ (self, udp_ip, udp_port, retransmission_timeout, src_address):
    self.in_transit = []
    self.seq_no = 0
    self.udp_ip = udp_ip
    self.udp_port = udp_port
    self.retransmission_timeout = retransmission_timeout
    self.src_address = EthAddr(src_address)

  def send(self, packet):
    log.debug('Sending this pilo packet:')
    log.debug(packet)
    packet.seq = self.seq_no
    self.seq_no += len(packet.pack())
    log.debug('len: ' + str(len(packet.pack())))

    self.send_pilo_broadcast(packet)
    self.in_transit.append(packet)
    core.callDelayed(self.retransmission_timeout, self.check_acked, packet)

  def check_acked(self, pilo_packet):
    if pilo_packet in self.in_transit:
      self.send_pilo_broadcast(pilo_packet)
      core.callDelayed(self.retransmission_timeout, self.check_acked, pilo_packet)

  def handle_ack(self, ack_packet):
    # TODO: Retransmit packet if we've received an out of order ack

    if not ack_packet.ACK:
      # if for some reason we get a packet here that isn't an ack, return
      return

    # TODO: Potentially add some checksum check
    for packet in self.in_transit:
      if (ack_packet.seq == packet.seq and
          ack_packet.ack == packet.seq + len(packet.pack())):

        self.in_transit.remove(packet)

  def send_synack(self, pilo_packet):
    ack_seq = pilo_packet.seq + len(pilo_packet.pack())
    seq_no = pilo_packet.seq

    synack_packet = pkt.pilo()
    synack_packet.src_address  = self.src_address
    synack_packet.dst_address  = EthAddr(pilo_packet.src_address)
    synack_packet.seq = seq_no
    synack_packet.ack = ack_seq
    synack_packet.ACK = True
    synack_packet.SYN = True

    log.debug('sending synack:')
    log.debug(synack_packet)

    self.send_pilo_broadcast(synack_packet)

  def send_syn(self, dst):
    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = self.src_address
    pilo_packet.dst_address  = pkt.packet_utils.mac_string_to_addr(dst)
    pilo_packet.SYN = True

    log.debug("sending syn packet:")
    log.debug(pilo_packet)

    self.send(pilo_packet)


class PiloReceiver(PiloTransport):
  def __init__ (self, src_address, udp_ip, udp_port):
    self.src_address = EthAddr(src_address)
    self.udp_ip = udp_ip
    self.udp_port = udp_port
    self.senders = []

  def handle_packet_in(self, pilo_packet, callback):
    log.debug('Handling packet in:')
    log.debug(pilo_packet)
    first_msg = True
    this_sender = None

    # Check if we've received a packet from this sender
    for sender in self.senders:
      if pkt.packet_utils.same_mac(sender['address'], pilo_packet.src_address):
        this_sender = sender
        first_msg = False

    # If we haven't received a packet from this sender
    # create new sender obj or dict
    # send ack
    # callback(pilo_packet)
    if first_msg:
      self.senders.append({
        'address': pilo_packet.src_address,
        'buffer': [],
        'seq_no': len(pilo_packet.pack())
        })
      self.send_ack(pilo_packet)
      callback(pilo_packet)
      return

    else:
      # If we have received a packet from this sender
      # check if this matches sender's seq_no
      if this_sender['seq_no'] == pilo_packet.ack:
        # If this packet matches the sender's seq_no
        # send ack for this packet
        # update this sender's seq_no
        # call handle_packet_in for all of the packets in the buffer if any
        # callback(pilo_packet)
        self.send_ack(pilo_packet)
        this_sender['seq_no'] += len(pilo_packet.pack())

        for msg in this_sender['buffer']:
          self.handle_packet_in(msg['packet'], msg['callback'])

        callback(pilo_packet)

      else:
        # If this packet does not match the sender's seq no
        # add this packet to their buffer
        this_sender['buffer'].append({
          'packet': pilo_packet,
          'callback': callback
          })


  def send_ack(self, pilo_packet):
    ack_seq = pilo_packet.seq + len(pilo_packet.pack())
    seq_no = pilo_packet.seq

    ack_packet = pkt.pilo()
    ack_packet.src_address  = self.src_address
    ack_packet.dst_address  = EthAddr(pilo_packet.src_address)
    ack_packet.seq = seq_no
    ack_packet.ack = ack_seq
    ack_packet.ACK = True

    packed = ack_packet.pack()

    log.debug('sending ack:')
    log.debug(ack_packet)

    self.send_pilo_broadcast(ack_packet)



