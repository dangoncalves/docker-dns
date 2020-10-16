#!/usr/bin/env/python3

import docker
import time
import os
import signal
from twisted.trial.unittest import TestCase
from multiprocessing import Process
from dockerDNS import DockerDNS
from dnslib.dns import DNSRecord
from ipaddress import IPv4Address, IPv4Network

CLIENT = docker.from_env()


def resolveDNS(query, server, port, type="A"):
    allowedTypes = ("A", "AAAA")
    if type not in allowedTypes:
        raise ValueError
    q = DNSRecord.question(query, type)
    answer_paquet = q.send(server, port, tcp=False)
    a = DNSRecord.parse(answer_paquet)
    return [str(a.rr[i].rdata) for i in range(len(a.rr))]


def areAnswersInNetworks(answers, networks_name):
    networks = [CLIENT.networks.list(names=network_name)[0]
                for network_name in networks_name]
    subnets = [IPv4Network(network.attrs['IPAM']['Config'][0]['Subnet'])
               for network in networks]
    IPs = [IPv4Address(answer) for answer in answers]
    tests = []
    for IP in IPs:
        for subnet in subnets:
            if IP in subnet:
                tests.append(IP)

    return len(IPs) == len(tests)


class BaseTest(TestCase):

    def __init__(self, *args, **kwargs):
        super(BaseTest, self).__init__(*args, **kwargs)

        self.network = "bridge"

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
            network=self.network
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
        oldNetwork = self.network
        self.network = "dockerdns_test"

        firstNetworks = self.dockerClient.networks.list(
            names=["dockerdns_test"])
        if firstNetworks:
            firstNetwork = firstNetworks[0]
        else:
            firstNetwork = self.dockerClient.networks.create(
                self.network)

        secondNetworks = self.dockerClient.networks.list(
            names=["another_dockerdns_test"])
        if secondNetworks:
            secondNetwork = secondNetworks[0]
        else:
            secondNetwork = self.dockerClient.networks.create(
                "another_dockerdns_test")

        self.start_container()
        secondNetwork.connect(self.defaultContainerName)
        # While we detach the container,
        # we have to wait it has fully started.
        time.sleep(self.sleepTimeStart)
        self.while_container_is_running([
            "dockerdns_test",
            "another_dockerdns_test"])
        # We wait again to ensure the DNS entry
        # was removed after container has stopped.
        time.sleep(self.sleepTimeDestroy)
        self.when_container_has_gone()

        firstNetwork.remove()
        secondNetwork.remove()
        self.network = oldNetwork


class TestDockerDNSIPv4(BaseTest):

    def __init__(self, *args, **kwargs):
        super(TestDockerDNSIPv4, self).__init__(*args, **kwargs)
        self.port = 35353
        self.listenAddress = "127.0.0.1"
        self.forwarders = "8.8.8.8"

    def while_container_is_running(self, networks=None):
        if networks is None:
            networks = [self.network]
        dnsAnswer = resolveDNS(self.defaultContainerName,
                               self.listenAddress,
                               self.port)
        self.assertTrue(areAnswersInNetworks(dnsAnswer, networks))

    def when_container_has_gone(self):
        dnsAnswer = resolveDNS(self.defaultContainerName,
                               self.listenAddress,
                               self.port)
        self.assertTrue(len(dnsAnswer) == 0)
