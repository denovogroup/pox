#!/usr/bin/env python
#
# Copyright 2011-2012 Andreas Wundsam
# Copyright 2011-2012 Colin Scott
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

from collections import namedtuple

import time
import re

import unittest
import sys
import os.path
import itertools

sys.path.append(os.path.dirname(__file__) + "/../../..")
from pox.pilo.pilo_transport import *
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet import pilo as pilo_packet
from pox.openflow.of_01 import *

class PiloPacketTest(unittest.TestCase):
  def setUp(self):
    pass


  def test_partial_acks(self):
    pkt = pilo_packet()
    pkt.seq = 2
    pkt.ack = 3

    pkt.set_partial_acks([5, 9, 10])
    self.assertEqual(pkt.partial_acks, 98)

    get_acks = pkt.get_partial_acks()
    self.assertEqual(get_acks, [5, 9, 10])

    holes = pkt.get_partial_ack_holes()
    self.assertEqual(holes, [4, 6, 7, 8])


if __name__ == '__main__':
  unittest.main()

