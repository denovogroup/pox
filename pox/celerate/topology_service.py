# Copyright 2015 Max Bittman
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
This is a messenger service for sending/receiving topology messages to/from
an "external controller" ie. a much larger grain time scale controller that
may have human interaction.

"""

from pox.core import core
from pox.messenger import *
from pox.openflow.topology import OpenFlowSwitch
from pox.topology.topology import *
import sys
import traceback
import json

log = core.getLogger()


class TopologyBot (ChannelBot):
  def _init (self, extra):
    core.listen_to_dependencies(self, ['topology'], short_attrs=True)
    self.count = 1001

  def _handle_MessageReceived (self, event, msg):
    log.debug('event: ' + str(event))
    log.debug('msg: ' + str(msg))
    log.debug('self.topology: ' + str(self.topology))
    log.debug('core.topology: ' + str(core.topology))
    try:
      self._parse_topology_msg(msg['msg'])
    except Exception as e:
      log.debug("Exception in _parse_topology_msg - %s:%s",
                sys.exc_info()[0].__name__,
                sys.exc_info()[1])

    event.con.send(reply(msg, msg = msg.get('msg')))

  def _parse_topology_msg (self, msg):
    log.debug('msg in parse topology: ' + str(msg))
    topology_dict = json.loads(msg)
    log.debug('topology_dict in parse topology: ' + str(msg))
    (edges, switches, hosts) = (topology_dict['edges'],
                                topology_dict['switches'],
                                topology_dict['hosts'])

    log.debug("topology: " + str((edges, switches, hosts)))

    all_switches = getEntitiesOfType (t=OpenFlowSwitch):
    all_hosts = getEntitiesOfType (t=Host):
    all_ports = getEntitiesOfType (t=Port):
    # First check in existing_switches for any dpids that aren't in
    # switches and remove them
    for existing_switch in all_switches:
      in_update = False
      for switch in switches:
        if existing_switch.id == switch['dpid']:
          in_update = True

      if not in_update:
        core.topology.removeEntity(existing_switch)

    for switch in switches:
      dpid = switch['dpid']
      ports = switch['ports']

      # Check if switch already in topology
      openflow_switch = self.topology.getEntityByID(dpid)
      # If already in topology, update?

      # If not already in topology, create switch and add to topology
      if not openflow_switch:
        openflow_switch = OpenFlowSwitch(dpid)
        self.topology.addEntity(openflow_switch)

      # First check existing ports in switch and check if they're in update
      self._check_add_ports(ports, openflow_switch)

    for existing_host in all_hosts:
      in_update = False
      for host in hosts:
        if existing_host.id == host['dpid']:
          in_update = True

      if not in_update:
        core.topology.removeEntity(existing_host)

    for host in hosts:
      dpid = host['dpid']
      ports = host['ports']

      # Check if host already in topology
      host = self.topology.getEntityByID(dpid)
      # If already in topology, update?

      # If not already in topology, create host and add to topology
      if not host:
        openflow_switch = OpenFlowSwitch(dpid)
        self.topology.addEntity(openflow_switch)

      # First check existing ports in switch and check if they're in update
      self._check_add_ports(ports, openflow_switch)

    for edge in edges:
      entity1 = edge['entity1']
      entity2 = edge['entity2']
      topology_entity1 = self.topology.getEntityByID(entity1['dpid'])
      topology_entity2 = self.topology.getEntityByID(entity2['dpid'])

      if topology_entity1 is None or topology_entity2 is None: return

      port1 = edge['port1']
      port2 = edge['port2']
      if port1 not in topology_entity1.ports or port2 not in topology_entity2.ports: return
        topology_entity1.ports[port1].addEntity(topology_entity2, single=True)
        topology_entity2.ports[port2].addEntity(topology_switch1, single=True)


  def _check_add_ports(ports, entity):
    for existing_port in entity.ports:
        in_update = False
        for port in ports:
          if self._ports_match(existing_port, port):
            in_update = True

        if not in_update:
          del entity.ports[existing_port.num]
          core.topology.removeEntity(existing_port)

      # Check if port update not already in topology
      # Port class takes num, hwAddr, name
      for port in ports:
        already_exists = False
        for existing_port in openflow_switch.ports:
          if self._ports_match(existing_port, port):
            already_exists = True

        if not already_exists:
          new_port = Port(port['num'], port['hwAddr'], port['name'])
          openflow_switch.ports[new_port.num] = new_port


  def _ports_match(topo_port, dict_port):
    return topo_port['num'] == topo_port.num and
           topo_port['hwAddr'] == topo_port.hwAddr and
           topo_port['name'] == topo_port.name


def launch (nexus = "MessengerNexus"):
  def _launch ():
    core.MessengerNexus.default_bot.add_bot(TopologyBot)

    # We'll be using the "topology" channel
    TopologyBot("topology")

    # We can register this so that we can use it for dependencies
    core.register(nexus + "_topology_service", object())

  core.call_when_ready(_launch, [nexus, "topology"])
