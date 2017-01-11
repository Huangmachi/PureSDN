# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
# Copyright (C) 2016 Huang MaChi at Chongqing University
# of Posts and Telecommunications, China.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
from mininet.util import dumpNodeConnections

import logging
import os

logging.basicConfig(filename='./fattree.log', level=logging.INFO)
logger = logging.getLogger(__name__)


class Fattree(Topo):
	logger.debug("Class Fattree")
	CoreSwitchList = []
	AggSwitchList = []
	EdgeSwitchList = []
	HostList = []

	def __init__(self, k, density):
		logger.debug("Class Fattree init")
		self.pod = k
		self.density = density
		self.iCoreLayerSwitch = (k/2)**2
		self.iAggLayerSwitch = k*k/2
		self.iEdgeLayerSwitch = k*k/2
		self.iHost = self.iEdgeLayerSwitch * density

		# Init Topo
		Topo.__init__(self)

	def createTopo(self):
		self.createCoreLayerSwitch(self.iCoreLayerSwitch)
		self.createAggLayerSwitch(self.iAggLayerSwitch)
		self.createEdgeLayerSwitch(self.iEdgeLayerSwitch)
		self.createHost(self.iHost)

	# Create Switch and Host
	def _addSwitch(self, number, level, switch_list):
		for i in xrange(1, number+1):
			PREFIX = str(level) + "00"
			if i >= 10:
				PREFIX = str(level) + "0"
			switch_list.append(self.addSwitch(PREFIX + str(i)))

	def createCoreLayerSwitch(self, NUMBER):
		logger.debug("Create Core Layer")
		self._addSwitch(NUMBER, 1, self.CoreSwitchList)

	def createAggLayerSwitch(self, NUMBER):
		logger.debug("Create Agg Layer")
		self._addSwitch(NUMBER, 2, self.AggSwitchList)

	def createEdgeLayerSwitch(self, NUMBER):
		logger.debug("Create Edge Layer")
		self._addSwitch(NUMBER, 3, self.EdgeSwitchList)

	def createHost(self, NUMBER):
		logger.debug("Create Host")
		for i in xrange(1, NUMBER+1):
			if i >= 100:
				PREFIX = "h"
			elif i >= 10:
				PREFIX = "h0"
			else:
				PREFIX = "h00"
			self.HostList.append(self.addHost(PREFIX + str(i), cpu=1.0/NUMBER))

	# Add Link
	def createLink(self, bw_c2a=10, bw_a2e=10, bw_h2a=10):
		logger.debug("Add link Core to Agg.")
		end = self.pod/2
		for x in xrange(0, self.iAggLayerSwitch, end):
			for i in xrange(0, end):
				for j in xrange(0, end):
					self.addLink(
						self.CoreSwitchList[i*end+j],
						self.AggSwitchList[x+i],
						bw=bw_c2a, max_queue_size=100, use_htb=True)   # use_htb=True

		logger.debug("Add link Agg to Edge.")
		for x in xrange(0, self.iAggLayerSwitch, end):
			for i in xrange(0, end):
				for j in xrange(0, end):
					self.addLink(
						self.AggSwitchList[x+i], self.EdgeSwitchList[x+j],
						bw=bw_a2e, max_queue_size=100, use_htb=True)

		logger.debug("Add link Edge to Host.")
		for x in xrange(0, self.iEdgeLayerSwitch):
			for i in xrange(0, self.density):
				self.addLink(
					self.EdgeSwitchList[x],
					self.HostList[self.density * x + i],
					bw=bw_h2a, max_queue_size=100, use_htb=True)

	def set_ovs_protocol_13(self,):
		self._set_ovs_protocol_13(self.CoreSwitchList)
		self._set_ovs_protocol_13(self.AggSwitchList)
		self._set_ovs_protocol_13(self.EdgeSwitchList)

	def _set_ovs_protocol_13(self, sw_list):
		for sw in sw_list:
			cmd = "sudo ovs-vsctl set bridge %s protocols=OpenFlow13" % sw
			os.system(cmd)


def set_host_ip(net, topo):
	hostlist = []
	for k in xrange(len(topo.HostList)):
		hostlist.append(net.get(topo.HostList[k]))
	i = 1
	j = 1
	for host in hostlist:
		host.setIP("10.%d.0.%d" % (i, j))
		j += 1
		if j == topo.density+1:
			j = 1
			i += 1

def install_proactive(net, topo):
	"""
		Install direct flow entries for edge switches.
	"""
	# Edge Switch
	for sw in topo.EdgeSwitchList:
		num = int(sw[-2:])
		sw = net.get(sw)

		# Downstream.
		for i in xrange(1, topo.density+1):
			cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
				'table=0,idle_timeout=0,hard_timeout=0,priority=10,arp, \
				nw_dst=10.%d.0.%d,actions=output:%d'" % (sw.name, num, i, topo.pod/2+i)
			os.system(cmd)
			cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
				'table=0,idle_timeout=0,hard_timeout=0,priority=10,ip, \
				nw_dst=10.%d.0.%d,actions=output:%d'" % (sw.name, num, i, topo.pod/2+i)
			os.system(cmd)

	# Aggregate Switch
	# Downstream.
	for sw in topo.AggSwitchList:
		num = int(sw[-2:])
		sw = net.get(sw)
		podList = []
		remainder = num % (topo.pod/2)
		if topo.pod == 4:
			if remainder == 0:
				podList = [num-1, num]
			elif remainder == 1:
				podList = [num, num+1]
		elif topo.pod == 8:
			if remainder == 0:
				podList = [num-3, num-2, num-1, num]
			elif remainder == 1:
				podList = [num, num+1, num+2, num+3]
			elif remainder == 2:
				podList = [num-1, num, num+1, num+2]
			elif remainder == 3:
				podList = [num-2, num-1, num, num+1]
			else:
				pass
		else:
			pass

		k = 1
		for i in podList:
			cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
				'table=0,idle_timeout=0,hard_timeout=0,priority=10,arp, \
				nw_dst=10.%d.0.0/16, actions=output:%d'" % (sw.name, i, topo.pod/2+k)
			os.system(cmd)
			cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
				'table=0,idle_timeout=0,hard_timeout=0,priority=10,ip, \
				nw_dst=10.%d.0.0/16, actions=output:%d'" % (sw.name, i, topo.pod/2+k)
			os.system(cmd)
			k += 1

	# Core Switch
	for sw in topo.CoreSwitchList:
		sw = net.get(sw)
		j = 1
		k = 1
		for i in xrange(1, len(topo.EdgeSwitchList)+1):
			cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
				'table=0,idle_timeout=0,hard_timeout=0,priority=10,arp, \
				nw_dst=10.%d.0.0/16, actions=output:%d'" % (sw.name, i, j)
			os.system(cmd)
			cmd = "ovs-ofctl add-flow %s -O OpenFlow13 \
				'table=0,idle_timeout=0,hard_timeout=0,priority=10,ip, \
				nw_dst=10.%d.0.0/16, actions=output:%d'" % (sw.name, i, j)
			os.system(cmd)
			k += 1
			if k == topo.pod/2 + 1:
				j += 1
				k = 1

def iperfTest(net, topo):
	logger.debug("Start iperfTEST")
	h001, h015, h016 = net.get(
		topo.HostList[0], topo.HostList[14], topo.HostList[15])
	# iperf Server
	h001.popen('iperf -s -u -i 1 > iperf_server_differentPod_result', shell=True)
	# iperf Server
	h015.popen('iperf -s -u -i 1 > iperf_server_samePod_result', shell=True)
	# iperf Client
	h016.cmdPrint('iperf -c ' + h001.IP() + ' -u -t 10 -i 1 -b 10m')
	h016.cmdPrint('iperf -c ' + h015.IP() + ' -u -t 10 -i 1 -b 10m')

def pingTest(net):
	logger.debug("Start Test all network")
	net.pingAll()

def createTopo(pod, density, ip="192.168.56.101", port=6653, bw_c2a=10, bw_a2e=10, bw_h2a=10):
	logging.debug("LV1 Create Fattree")
	topo = Fattree(pod, density)
	topo.createTopo()
	topo.createLink(bw_c2a=bw_c2a, bw_a2e=bw_a2e, bw_h2a=bw_h2a)
	logging.debug("LV1 Start Mininet")
	CONTROLLER_IP = ip
	CONTROLLER_PORT = port
	net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True)
	net.addController(
		'controller', controller=RemoteController,
		ip=CONTROLLER_IP, port=CONTROLLER_PORT)
	net.start()
	# Set OVS's protocol as OF13.
	topo.set_ovs_protocol_13()
	# Set hosts IP addresses.
	set_host_ip(net, topo)
	# Install proactive flow entries
	install_proactive(net, topo)
	# logger.debug("LV1 dumpNode")
	# dumpNodeConnections(net.hosts)
	# pingTest(net)
	# iperfTest(net, topo)

	CLI(net)
	net.stop()

if __name__ == '__main__':
	setLogLevel('info')
	if os.getuid() != 0:
		logger.debug("You are NOT root")
	elif os.getuid() == 0:
		# createTopo(4, 2)
		createTopo(8, 4)
