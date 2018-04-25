#!/usr/bin/env python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI

from eBPFSwitch import eBPFSwitch, eBPFHost

from time import sleep

class SingleSwitchTopo(Topo):
    def __init__(self, i,**opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1',
            switch_path="../inputqueuedswitch/inputqueuedswitch")

        for h in xrange(i): #TODO number of hosts
            host = self.addHost('h%d' % (h + 1),
                                ip = "10.0.%d.10/24" % h,
                                mac = '00:04:00:00:00:%02x' %h)

            self.addLink(host, switch)

def main(i):
    topo = SingleSwitchTopo(i)
    net = Mininet(topo = topo, host = eBPFHost, switch = eBPFSwitch, controller = None)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    i = int(input('Number of hosts: '))
    main(i)
