#!/usr/bin/env python3
"""Resolve docker container's name into IPv4 address"""

import docker
from ipaddress import ip_address, IPv4Address, IPv6Address
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
            containerNetworks = c.attrs["NetworkSettings"]["Networks"]
            for k, v in containerNetworks.items():
                containerIPv4 = v["IPAddress"]
                containerIPv6 = v["GlobalIPv6Address"]
                if not containerIPv6:
                    containerIPv6 = None

                self.addContainer(containerName, containerIPv4, containerIPv6)

    def addContainer(self, containerName, containerIPv4, containerIPv6=None):
        if containerName not in self.runningContainers:
            self.runningContainers[containerName] = []
        self.runningContainers[containerName].append(containerIPv4)
        if containerIPv6:
            self.runningContainers[containerName].append(containerIPv6)

    def removeContainer(self, containerName):
        self.runningContainers.pop(containerName, None)

    def __lookup(self, query, timeout=None, type="A"):
        allowedTypes = ("A", "AAAA")
        if type not in allowedTypes:
            raise ValueError
        domain = query.decode()
        if domain in self.runningContainers:
            answers = []
            authority = []
            additional = []
            for address in self.runningContainers[domain]:
                if ((type == "A"
                        and not isinstance(ip_address(address), IPv4Address))
                    or (type == "AAAA"
                        and not isinstance(ip_address(address), IPv6Address))):
                    continue
                record = getattr(dns, "Record_%s" % type)
                p = record(address=address.encode())
                dnsType = getattr(dns, "%s" % type)
                answer = dns.RRHeader(name=query, payload=p, type=dnsType)
                answers.append(answer)
            return defer.succeed((answers, authority, additional))
        else:
            return None

    def lookupAddress(self, query, timeout=None):
        response = self.__lookup(query, timeout, "A")
        if response:
            return response
        else:
            return super().lookupAddress(query, timeout)

    def lookupIPV6Address(self, query, timeout=None):
        response = self.__lookup(query, timeout, "AAAA")
        if response:
            return response
        else:
            return super().lookupIPV6Address(query, timeout)


class EventsListener(Thread):
    """Listen on start and die events."""
    def __init__(self, resolver):
        super().__init__()
        self.resolver = resolver
        self.eventListener = None

    def run(self):
        self.eventListener = self.resolver.dockerClient.events(
                            filters={"event": ["connect", "disconnect"]},
                            decode=True)
        for e in self.eventListener:
            callback = getattr(self, e["Action"] + "Callback")
            callback(e)

    def join(self, timeout=None):
        self.eventListener.close()
        super().join(timeout)

    def connectCallback(self, event):
        containerID = event["Actor"]["Attributes"]["container"]
        api = self.resolver.dockerClient.api
        container = api.inspect_container(containerID)
        containerName = container["Name"].lstrip('/')
        containerNetworks = container["NetworkSettings"]["Networks"]

        for k, v in containerNetworks.items():
            containerIPv4 = v["IPAddress"]
            containerIPv6 = v["GlobalIPv6Address"]
            shouldAddContainer = True
            # ContainerNetworks contains all the networks. So if we connect a
            # second (or third) network after container started, we fire
            # connect event several times. This means we should ensure that
            # containerName appears once in resolver.runningContainers list.
            if containerName in self.resolver.runningContainers:
                thisContainer = self.resolver.runningContainers[containerName]
                if containerIPv4 in thisContainer:
                    shouldAddContainer = False

            if not containerIPv6:
                containerIPv6 = None

            if shouldAddContainer:
                self.resolver.addContainer(containerName,
                                           containerIPv4,
                                           containerIPv6)

    def disconnectCallback(self, event):
        containerID = event["Actor"]["Attributes"]["container"]
        api = self.resolver.dockerClient.api
        try:
            container = api.inspect_container(containerID)
            containerName = container["Name"].lstrip('/')
            self.resolver.removeContainer(containerName)
        except docker.errors.NotFound:
            pass


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
