#!/usr/bin/env/python3

import docker
import time
import os
import signal
from twisted.trial.unittest import TestCase
from multiprocessing import Process
from dockerDNS import DockerDNS
from dnslib.dns import DNSRecord
from ipaddress import ip_address, ip_network, IPv6Address

CLIENT = docker.from_env()


def resolveDNS(query, server, port, type="A"):
    allowedTypes = ("A", "AAAA")
    if type not in allowedTypes:
        raise ValueError
    ipv6Server = False
    if isinstance(ip_address(server), IPv6Address):
        ipv6Server = True
    q = DNSRecord.question(query, type)
    answer_paquet = q.send(server, port, tcp=False, ipv6=ipv6Server)
    a = DNSRecord.parse(answer_paquet)
    return [str(a.rr[i].rdata) for i in range(len(a.rr))]


def areAnswersInNetworks(answers, networks_name):
    networks = [CLIENT.networks.list(names=network_name)[0]
                for network_name in networks_name]
    subnets = []
    for network in networks:
        for config in network.attrs['IPAM']['Config']:
            subnet = config['Subnet']
            subnets.append(ip_network(subnet))

    IPs = [ip_address(answer) for answer in answers]
    tests = []
    for IP in IPs:
        for subnet in subnets:
            if IP in subnet:
                tests.append(IP)

    return len(IPs) == len(tests) and len(IPs) > 0


class BaseTest(TestCase):

    def __init__(self, *args, **kwargs):
        super(BaseTest, self).__init__(*args, **kwargs)

        self.networks = ["bridge"]

        self.sleepTimeStart = 2
        self.sleepTimeDestroy = 2

        self.defaultContainerCommand = "sleep 3"
        self.defaultContainerName = "test.dockerdns.io"

        self.port = None
        self.listenAddress = None
        self.forwarders = None

        self.process = None

    def dockerDNSProcess(self):
        if (not self.port
                or not self.listenAddress
                or not self.forwarders):
            raise ValueError
        p = DockerDNS(self.port, self.listenAddress, self.forwarders)
        p.start()
        p.clean()

    def setUp(self):
        self.dockerClient = CLIENT

        self.process = Process(target=self.dockerDNSProcess)
        self.process.start()

    def tearDown(self):
        os.kill(self.process.pid, signal.SIGTERM)
        self.process.join()

    def start_container(self):
        self.dockerClient.containers.run(
            "debian:buster",
            self.defaultContainerCommand,
            remove=True,
            detach=True,
            name=self.defaultContainerName,
            network=self.networks[0]
        )

    def while_container_is_running(self, networks):
        raise NotImplementedError

    def when_container_has_gone(self):
        raise NotImplementedError

    def test_basic_dns_request(self):
        self.start_container()
        # While we detach the container,
        # we have to wait it has fully started.
        time.sleep(self.sleepTimeStart)
        self.while_container_is_running()
        # We wait again to ensure the DNS entry
        # was removed after container has stopped.
        time.sleep(self.sleepTimeDestroy)
        self.when_container_has_gone()

    def test_docker_network(self):
        oldNetworks = self.networks
        self.networks = ["dockerdns_test", "another_dockerdns_test"]

        i = 0
        dockerNetworks = []
        for network in self.networks:
            subnet = "fc01:122:%s::/64" % i
            i += 1
            IPAMPools = [docker.types.IPAMPool(subnet=subnet)]
            IPAMConfig = docker.types.IPAMConfig(pool_configs=IPAMPools)
            dockerNetwork = self.dockerClient.networks.list(names=[network])
            if len(dockerNetwork) >= 1:
                dockerNetworks.append(dockerNetwork[0])
            else:
                dockerNetworks.append(self.dockerClient.networks.create(
                    network,
                    enable_ipv6=True,
                    ipam=IPAMConfig))

        self.start_container()
        for dockerNetwork in dockerNetworks[1:]:
            dockerNetwork.connect(self.defaultContainerName)
        # While we detach the container,
        # we have to wait it has fully started.
        time.sleep(self.sleepTimeStart)
        self.while_container_is_running(self.networks)
        # We wait again to ensure the DNS entry
        # was removed after container has stopped.
        time.sleep(self.sleepTimeDestroy)
        self.when_container_has_gone()

        for dockerNetwork in dockerNetworks:
            dockerNetwork.remove()
        self.network = oldNetworks


class TestDockerDNSIPv4(BaseTest):

    def __init__(self, *args, **kwargs):
        super(TestDockerDNSIPv4, self).__init__(*args, **kwargs)
        self.port = 35353
        self.listenAddress = "127.0.0.1"
        self.forwarders = "8.8.8.8"

    def while_container_is_running(self, networks=None):
        if networks is None:
            networks = self.networks
        dnsAnswer = resolveDNS(self.defaultContainerName,
                               self.listenAddress,
                               self.port)
        self.assertTrue(areAnswersInNetworks(dnsAnswer, networks))

    def when_container_has_gone(self):
        dnsAnswer = resolveDNS(self.defaultContainerName,
                               self.listenAddress,
                               self.port)
        self.assertTrue(len(dnsAnswer) == 0)


class TestDockerDNSIPv6(BaseTest):

    def __init__(self, *args, **kwargs):
        super(TestDockerDNSIPv6, self).__init__(*args, **kwargs)
        self.port = 35353
        self.listenAddress = "::1"
        self.forwarders = "2001:4860:4860::8888"

    def while_container_is_running(self, networks=None):
        if networks is None:
            networks = self.networks
        dnsAnswer = resolveDNS(self.defaultContainerName,
                               self.listenAddress,
                               self.port,
                               type="AAAA")
        self.assertTrue(areAnswersInNetworks(dnsAnswer, networks))

    def when_container_has_gone(self):
        dnsAnswer = resolveDNS(self.defaultContainerName,
                               self.listenAddress,
                               self.port,
                               type="AAAA")
        self.assertTrue(len(dnsAnswer) == 0)
