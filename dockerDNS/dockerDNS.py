#!/usr/bin/env python3
"""Resolve docker container's name into IPv4 address"""

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
        self.eventListener = None

    def run(self):
        self.eventListener = self.resolver.dockerClient.events(
                            filters={"event": ["start", "die"]},
                            decode=True)
        for e in self.eventListener:
            callback = getattr(self, e["Action"] + "Callback")
            callback(e)

    def join(self, timeout=None):
        self.eventListener.close()
        super().join(timeout)

    def startCallback(self, event):
        containerName = event["Actor"]["Attributes"]["name"]
        api = self.resolver.dockerClient.api
        container = api.inspect_container(containerName)
        containerIPv4 = container["NetworkSettings"]["IPAddress"]
        self.resolver.addContainer(containerName, containerIPv4)

    def dieCallback(self, event):
        containerName = event["Actor"]["Attributes"]["name"]
        self.resolver.removeContainer(containerName)


class DockerDNS():
    """Start and stop DockerDNS Service"""
    def __init__(self, port=None, listenAddress=None, forwarders=None):
        self.port = port
        self.listenAddress = listenAddress
        self.forwarders = forwarders

        self.eventsListener = None

        self.udp_listener = None
        self.tcp_listener = None

        if self.port is None:
            self.port = DNS_PORT
        if self.listenAddress is None:
            self.listenAddress = LISTEN_ADDRESS

    def start(self):
        """Configure and execute the DNS server."""
        dockerClient = docker.from_env()
        resolver = DockerResolver(dockerClient=dockerClient,
                                  servers=self.forwarders)

        self.eventsListener = EventsListener(resolver)
        self.eventsListener.start()
        factory = server.DNSServerFactory(clients=[resolver])
        protocol = dns.DNSDatagramProtocol(controller=factory)
        self.udp_listener = reactor.listenUDP(port=self.port,
                                              protocol=protocol,
                                              interface=self.listenAddress)
        self.tcp_listener = reactor.listenTCP(port=self.port,
                                              factory=factory,
                                              interface=self.listenAddress)
        reactor.run()

    def clean(self):
        """Clean all the resources"""
        self.stop()
        self.eventsListener.join()

    def stop(self):
        """Stop the reactor if running"""
        if reactor.running:
            self.udp_listener.stopListening()
            self.tcp_listener.stopListening()
            reactor.stop()
