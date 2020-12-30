#!/usr/bin/env python3

import docker
import sys
from ipaddress import ip_network, IPv6Network

client = docker.from_env()

for network in client.networks.list():
    subnets = network.attrs['IPAM']['Config']
    for subnet in subnets:
        address = ip_network(subnet['Subnet'])
        if isinstance(address, IPv6Network):
            print("Docker has ipv6 support")
            sys.exit(0)

print("Docker has no ipv6 support")
sys.exit(1)
