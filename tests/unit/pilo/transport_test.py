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
from pox.pilo.pilo_client import *
from pox.pilo.pilo_controller import *
from pox.lib.revent.revent import EventMixin
from pox.openflow.of_01 import *

class MockConnection(EventMixin):
  def __init__(self):
    self.dpid =1

class MockPiloClient(EventMixin):
  _eventMixin_events = set([PiloPacketIn])
  def __init__ (self, connection, **kwargs):
    EventMixin.__init__(self)
    self.connection = connection

    for name, value in kwargs.items():
      setattr(self, name, value)

class MockPiloController(EventMixin):
  _eventMixin_events = set([PiloPacketIn])
  def __init__ (self, connection, **kwargs):
    EventMixin.__init__(self)
    self.connection = connection

    for name, value in kwargs.items():
      setattr(self, name, value)


class PiloClient (EventMixin):
  """
  A Pilo object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """


class PiloTransportConfigTest(unittest.TestCase):
  def setUp(self):
    self.conn = MockConnection()
    self.client = MockPiloClient(self.conn)
    self.controller = MockPiloController(self.conn)
    self.transport_config = PiloTransportConfig(self.client, '10.1.255.255', '9999', '10.1.100.1', '00:00:00:00:00:01', 5, 40)


  def test_create(self):
    c = PiloTransportConfig(self.client, '10.1.255.255', '9999', '10.1.100.1', '00:00:00:00:00:01', 5, 40)
    self.assertEqual(c.udp_ip, '10.1.255.255')
    self.assertEqual(c.udp_port, '9999')
    self.assertEqual(c.src_ip, '10.1.100.1')
    self.assertEqual(c.src_address, EthAddr('00:00:00:00:00:01'))
    self.assertEqual(c.retransmission_timeout, 5)
    self.assertEqual(c.heartbeat_interval, 40)

  def test_to_string(self):
    log_string = """PiloTransportConfig: src_address=00:00:00:00:00:01
                    udp_port=9999
                    src_ip=10.1.100.1
                    udp_ip=10.1.255.255
                    heartbeat_interval=40
                    retransmission_timeout=5
"""

    pat = re.compile(r'\s+')
    self.assertEqual(pat.sub('', str(self.transport_config)), pat.sub('', log_string))


class PiloTransportTest(unittest.TestCase):
  def setUp(self):
    self.conn = MockConnection()
    self.client = MockPiloClient(self.conn)
    self.transport_config = PiloTransportConfig(self.client, '10.1.255.255', '9999', '10.1.100.1', '00:00:00:00:00:01', 5, 40)

  def test_create(self):
    transport = PiloTransport(self.client, '10.1.255.255', '9999', '10.1.100.1', '00:00:00:00:00:01', 5, 40)
    self.assertEqual(transport.config.udp_ip, '10.1.255.255')
    self.assertEqual(transport.config.udp_port, '9999')
    self.assertEqual(transport.config.src_ip, '10.1.100.1')
    self.assertEqual(transport.config.src_address, EthAddr('00:00:00:00:00:01'))
    self.assertEqual(transport.config.retransmission_timeout, 5)
    self.assertEqual(transport.config.heartbeat_interval, 40)

if __name__ == '__main__':
  unittest.main()

