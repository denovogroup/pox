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


#======================================================================
#
#                           PILO Header Format
#
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                  Source Hardware address                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                Destination Hardware address                   |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |A|S|F|H|                       |                               |
#  |C|Y|I|R|                       |              TTL              |
#  |K|N|N|B|                       |                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                             data                              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#======================================================================

# TODO: Need to figure out options/flags - do we need an ack field? Any other options?

import struct
from packet_utils       import *
from socket import htons
from socket import htonl

from packet_base import packet_base

from pox.lib.addresses import *


import logging
log = logging.getLogger('packet')

ETHER_ANY            = EthAddr(b"\x00\x00\x00\x00\x00\x00")
ETHER_BROADCAST      = EthAddr(b"\xff\xff\xff\xff\xff\xff")

class pilo(packet_base):
    "PILO packet struct"

    MIN_LEN = 24

    TTL_INIT = 12 # TODO:Probably want to better test this?

    ACK_flag = 0x01
    SYN_flag = 0x02
    FIN_flag = 0x04
    HRB_flag = 0x08

    @property
    def ACK (self): return True if self.flags & self.ACK_flag else False

    @property
    def SYN (self): return True if self.flags & self.SYN_flag else False

    @property
    def FIN (self): return True if self.flags & self.FIN_flag else False

    @property
    def HRB (self): return True if self.flags & self.HRB_flag else False

    @ACK.setter
    def ACK (self, value): self._setflag(self.ACK_flag, value)

    @SYN.setter
    def SYN (self, value): self._setflag(self.SYN_flag, value)

    @FIN.setter
    def FIN (self, value): self._setflag(self.FIN_flag, value)

    @HRB.setter
    def HRB (self, value): self._setflag(self.HRB_flag, value)

    def _setflag (self, flag, value):
      self.flags = (self.flags & ~flag) | (flag if value else 0)

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev

        self.src_address  = 0  # 32 bit
        self.dst_address  = 0  # 32 bit
        self.seq      = 0  # 32 bit
        self.ack      = 0  # 32 bit
        self.flags    = 0  # flags 16 bits
        self.ttl      = self.TTL_INIT  # ttl 16 bits
        self.next     = b''

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        f = ''
        if self.ACK: f += 'A'
        if self.SYN: f += 'S'
        if self.FIN: f += 'F'
        if self.HRB: f += 'H'

        s = '[PILO %s>%s seq:%s ack:%s f:%s ttl:%s len:%s]' % (self.src_address,
            self.dst_address, self.seq, self.ack, f, self.ttl, len(self.pack()))

        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        dlen = len(raw)
        if dlen < pilo.MIN_LEN:
            self.msg('(pilo parse) warning PILO packet data too short to parse header: data len %u' % (dlen,))
            return

        self.src_address  = EthAddr(raw[:6])
        self.dst_address= EthAddr(raw[6:12])

        (self.seq, self.ack, self.flags, self.ttl) \
            = struct.unpack('!IIHH', raw[12:pilo.MIN_LEN])

        self.hdr_len = pilo.MIN_LEN ## TODO: should this be dynamic or will we have fixed header size?
        self.payload_len = dlen - self.hdr_len

        self.next   = raw[self.hdr_len:]
        self.parsed = True

    def hdr(self, payload):

        dst = self.dst_address
        src = self.src_address
        if type(dst) is EthAddr:
          dst = dst.toRaw()
        if type(src) is EthAddr:
          src = src.toRaw()

        header = struct.pack('!6s6sIIHH', src, dst,
                 self.seq, self.ack, self.flags, self.ttl)

        return header

    # In order to compare packets, we can use:
    # http://stackoverflow.com/questions/390250/elegant-ways-to-support-equivalence-equality-in-python-classes/25176504#25176504
    # Likely this should actually be implemented for all POX packets
    # but I'm going to pass on that now - maxb
    def __eq__(self, other):
        """Override the default Equals behavior"""
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return NotImplemented

    def __ne__(self, other):
        """Define a non-equality test"""
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

    def __hash__(self):
        """Override the default hash behavior (that returns the id or the object)"""
        return hash(tuple(sorted(self.__dict__.items())))
