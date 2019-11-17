#!/usr/bin/env python3
"""
Resolve docker container's name into IPv4 address

  python3 docker-dns.py
"""

import os
import docker
from threading import Thread
from twisted.internet import reactor, defer
from twisted.names import client, dns, server


LISTEN_ADDRESS = "127.0.0.1"
DNS_PORT = 53


class DockerResolver(client.Resolver):
    """Resolve container name into IP address."""
    def __init__(self, dockerClient, servers=None):
        super().__init__(resolv=None, servers=servers)
        self.dockerClient = dockerClient
        self.runningContainers = {}
        for c in dockerClient.containers.list():
            containerName = c.attrs["Name"][1:]
            containerBridge = c.attrs["NetworkSettings"]["Networks"]["bridge"]
            containerIPv4 = containerBridge["IPAddress"]
            self.addContainer(containerName, containerIPv4)

    def addContainer(self, containerName, containerIPv4):
        self.runningContainers[containerName] = containerIPv4

    def removeContainer(self, containerName):
        self.runningContainers.pop(containerName, None)

    def lookupAddress(self, query, timeout=None):
        domain = query.decode()
        if domain in self.runningContainers:
            p = dns.Record_A(address=self.runningContainers[domain].encode())
            answer = dns.RRHeader(name=query, payload=p)
            answers = [answer]
            authority = []
            additional = []
            return defer.succeed((answers, authority, additional))
        else:
            return super().lookupAddress(query, timeout)


class EventsListener(Thread):
    """Listen on start and die events."""
    def __init__(self, resolver):
        super().__init__()
        self.resolver = resolver

    def run(self):
        eventListener = self.resolver.dockerClient.events(
                            filters={"event": ["start", "die"]},
                            decode=True)
        for e in eventListener:
            callback = getattr(self, e["Action"] + "Callback")
            callback(e)

    def startCallback(self, event):
        containerName = event["Actor"]["Attributes"]["name"]
        api = self.resolver.dockerClient.api
        container = api.inspect_container(containerName)
        containerIPv4 = container["NetworkSettings"]["IPAddress"]
        self.resolver.addContainer(containerName, containerIPv4)

    def dieCallback(self, event):
        containerName = event["Actor"]["Attributes"]["name"]
        self.resolver.removeContainer(containerName)


def run(port=DNS_PORT, listenAddress=LISTEN_ADDRESS, forwarders=None):
    """Configure and execute the DNS server."""
    dockerClient = docker.from_env()
    resolver = DockerResolver(dockerClient=dockerClient,
                              servers=forwarders)
    eventsListener = EventsListener(resolver)
    eventsListener.start()
    factory = server.DNSServerFactory(clients=[resolver])
    protocol = dns.DNSDatagramProtocol(controller=factory)
    reactor.listenUDP(port=port, protocol=protocol, interface=listenAddress)
    reactor.listenTCP(port=port, factory=factory, interface=listenAddress)
    reactor.run()
    eventsListener.join(1)
    # For an unknown reason sys.exit() does not work
    # so we use this hack.
    os._exit(0)
