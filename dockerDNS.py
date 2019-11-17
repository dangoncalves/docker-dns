#!/usr/bin/env python3
"""
Resolve docker container's name into IPv4 address

  python3 docker-dns.py
"""


import argparse
from dockerDNS import DNS_PORT, LISTEN_ADDRESS, run


def getForwarders(forwarders=None, listenAddress=LISTEN_ADDRESS):
    """
    Reads forwarders from arguments or from resolv.conf and create a list of
    tuples containing the forwarders' IP and the port.
    """
    if forwarders is None:
        forwarders = []
        with open("/etc/resolv.conf", "r") as resolvconf:
            for line in resolvconf:
                if line.startswith("nameserver"):
                    if line[11:-1] == listenAddress:
                        continue
                    else:
                        forwarders.append((line[11:-1], DNS_PORT))
            if len(forwarders) == 0:
                forwarders = None
    else:
        forwarders = forwarders.split(",")
        forwarders = [(address, DNS_PORT) for address in forwarders]
    return forwarders



if __name__ == "__main__":
    description = "Resolve docker container's name into IPv4 address"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--port",
                        type=int,
                        default=DNS_PORT)
    parser.add_argument("--listen-address",
                        dest="listenAddress",
                        default=LISTEN_ADDRESS)
    parser.add_argument("--forwarders",
                        default=None)
    options = parser.parse_args()
    forwarders = getForwarders(forwarders=options.forwarders,
                               listenAddress=options.listenAddress)
    run(port=options.port,
              listenAddress=options.listenAddress,
              forwarders=forwarders)
