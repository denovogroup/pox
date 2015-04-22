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
    self.receivers = []

  def send(self, packet, seq_no=None, callback=None):
    log.debug('Sending this pilo packet:')
    log.debug(packet)
    log.debug('seq_no passed in:')
    log.debug(seq_no)

    first_msg = True

    # Check if we've sent a packet to this sender
    for receiver in self.receivers:
      if pkt.packet_utils.same_mac(receiver['address'], packet.dst_address):
        this_receiver = receiver
        first_msg = False

    if first_msg:
      this_receiver = {
        'address': packet.dst_address,
        'seq_no': 0
        }
      self.receivers.append(this_receiver)

    if seq_no is None:
      packet.seq = this_receiver['seq_no']
      this_receiver['seq_no'] += len(packet.pack())

    self.send_pilo_broadcast(packet)
    self.in_transit.append(packet)
    core.callDelayed(self.retransmission_timeout, self.check_acked, packet, callback=callback)

  def check_acked(self, pilo_packet, callback=None):
    log.debug('checking if acked:')
    log.debug(pilo_packet)

    log.debug('in self.in_transit:')
    for p in self.in_transit:
      log.debug(p)
      log.debug('packet len:' + str(len(p.pack())))

    if pilo_packet in self.in_transit:
      log.debug('is still in transit')
      self.send_pilo_broadcast(pilo_packet)
      core.callDelayed(self.retransmission_timeout, self.check_acked, pilo_packet, callback=callback)

    else:
      log.debug('is not still in transit')
      log.debug('callback:')
      log.debug(callback)
      # TODO: This should really be evented, but it's easiest to do it this way for now
      if callback:
        callback(pilo_packet)

  def handle_ack(self, ack_packet):
    # TODO: Retransmit packet if we've received an out of order ack

    if not ack_packet.ACK:
      # if for some reason we get a packet here that isn't an ack, return
      return

    log.debug('Handling ack:')
    log.debug(ack_packet)

    log.debug('In transit:')
    # TODO: Potentially add some checksum check
    for packet in self.in_transit:
      log.debug(packet)
      if (ack_packet.seq == packet.seq and
          ack_packet.ack == packet.seq + len(packet.pack())):

        self.in_transit.remove(packet)

  def terminate_connection(self, address):
    for receiver in self.receivers:
      if pkt.packet_utils.same_mac(receiver['address'], address):
        self.receivers.remove(receiver)
        for packet in self.in_transit:
          if pkt.packet_utils.same_mac(receiver['address'], address):
            self.in_transit.remove(packet)

  def handle_fin(self, packet, callback):
    if not packet.FIN:
      # if for some reason we get a packet here that isn't a fin, return
      return

    def fin_callback(packet):
      # We've received a ACK from our FINACK and we can remove from our list of receivers
      # We also want to clear any in_transit packets
      # packet is the FINACK that we sent
      self.terminate_connection(packet.dst_address)
      callback(packet)

    log.debug('we\'re gonna send the finack here')
    log.debug('fin = ' + str(packet))

    ack_seq = packet.seq + len(packet.pack())
    seq_no = packet.seq

    finack_packet = pkt.pilo()
    finack_packet.src_address  = self.src_address
    finack_packet.dst_address  = EthAddr(packet.src_address)
    finack_packet.seq = seq_no
    finack_packet.ack = ack_seq
    finack_packet.ACK = True
    finack_packet.FIN = True

    log.debug('finack = ' + str(finack_packet))

    self.send(finack_packet, seq_no=seq_no, callback=fin_callback)

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

  def send_fin(self, dst):
    pilo_packet = pkt.pilo()
    pilo_packet.src_address  = self.src_address
    pilo_packet.dst_address  = dst
    pilo_packet.FIN = True

    log.debug("sending FIN packet:")
    log.debug(pilo_packet)

    def handle_finack(finack_packet):
      log.debug('received FINACK')
      self.terminate_connection(finack_packet.dst_address)

    self.send(pilo_packet, callback=handle_finack)



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

    log.debug('Senders: ')
    log.debug(self.senders)

    # Check if we've received a packet from this sender
    for sender in self.senders:
      if pkt.packet_utils.same_mac(sender['address'], pilo_packet.src_address):
        this_sender = sender
        first_msg = False

    log.debug('First msg: ' + str(first_msg))
    # If we haven't received a packet from this sender
    # create new sender obj or dict
    # send ack
    # callback(pilo_packet)
    if first_msg:
      self.senders.append({
        'address': pilo_packet.src_address,
        'buffer': [],
        'seq_no': pilo_packet.seq + len(pilo_packet.pack())
        })
      self.send_ack(pilo_packet)
      callback(pilo_packet)
      return

    elif pilo_packet.FIN:
      # This is hackish
      self.send_ack(pilo_packet)
      callback(pilo_packet)

    else:
      # If we have received a packet from this sender
      # check if this matches sender's seq_no
      log.debug('this_sender:')
      log.debug(this_sender)

      if this_sender['seq_no'] == pilo_packet.seq:
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
        # add this packet to their buffer if it's not below current seq no
        already_buffered = False
        for buffered in this_sender['buffer']:
          if buffered['packet'] == pilo_packet:
            already_buffered = True

        if pilo_packet.seq > this_sender['seq_no'] and not already_buffered:
          this_sender['buffer'].append({
            'packet': pilo_packet,
            'callback': callback
            })

  def fin_callback(self, sent_fin, received_ack):
    log.debug('inside fin_callback')
    log.debug('sent_fin: ' + str(sent_fin))
    log.debug('received_ack: ' + str(received_ack))

    assert sent_fin.FIN
    assert received_ack.ACK

    assert sent_fin.src_address == received_ack.dst_address
    assert sent_fin.dst_address == received_ack.src_address

    # Remove this sender from senders
    for sender in self.senders:
      if pkt.packet_utils.same_mac(sender['address'], sent_finack.dst_address):
        self.senders.remove(sender)


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



