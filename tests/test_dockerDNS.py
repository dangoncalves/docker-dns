#!/usr/bin/env/python3

import unittest
import docker
import time
import os
import signal
from multiprocessing import Process
from dockerDNS import DockerDNS
from dnslib.dns import DNSRecord
from ipaddress import IPv4Address, IPv4Network

CLIENT = docker.from_env()


def resolveDNS(query, server, port):
    q = DNSRecord.question(query)
    answer_paquet = q.send(server, port, tcp=False)
    a = DNSRecord.parse(answer_paquet)
    if len(a.rr) > 0:
        return str(a.rr[0].rdata)
    else:
        return ""


def isAnswerInNetwork(answer, network_name):
    network = CLIENT.networks.list(names=network_name)[0]
    subnet = IPv4Network(network.attrs['IPAM']['Config'][0]['Subnet'])
    ip = IPv4Address(answer)

    return ip in subnet


class TestDockerDNS(unittest.TestCase):

    def dockerDNSProcess(self):
        p = DockerDNS(port=35353,
                      listenAddress="127.0.0.1",
                      forwarders="8.8.8.8")
        p.start()
        p.clean()

    def setUp(self):
        self.dockerClient = CLIENT

        self.process = Process(target=self.dockerDNSProcess)
        self.process.start()

    def tearDown(self):
        os.kill(self.process.pid, signal.SIGTERM)
        self.process.join()

    def test_basic_dns_request(self):
        self.dockerClient.containers.run(
            "debian:buster",
            "sleep 3",
            remove=True,
            detach=True,
            name="test.dockerdns.io"
        )

        # While we detach the container,
        # we have to wait it has fully started.
        time.sleep(2)
        dnsAnswer = resolveDNS("test.dockerdns.io", "127.0.0.1", 35353)
        self.assertTrue(isAnswerInNetwork(dnsAnswer, "bridge"))

        # We wait again to ensure the DNS entry
        # was removed after container has stopped.
        time.sleep(2)
        dnsAnswer = resolveDNS("test.dockerdns.io", "127.0.0.1", 35353)
        self.assertTrue(dnsAnswer == "")

    def test_docker_network(self):
        first_network = self.dockerClient.networks.create(
            "test_dockerdns")
        second_network = self.dockerClient.networks.create(
            "another_test_dockerdns")
        self.dockerClient.containers.run(
            "debian:buster",
            "sleep 3",
            remove=True,
            detach=True,
            name="test.dockerdns.io",
            network="test_dockerdns"
        )
        second_network.connect("test.dockerdns.io")

        # While we detach the container,
        # we have to wait it has fully started.
        time.sleep(2)
        dnsAnswer = resolveDNS("test.dockerdns.io", "127.0.0.1", 35353)
        self.assertTrue(isAnswerInNetwork(dnsAnswer, "test_dockerdns"))

        # We wait again to ensure the DNS entry
        # was removed after container has stopped.
        time.sleep(2)
        dnsAnswer = resolveDNS("test.dockerdns.io", "127.0.0.1", 35353)
        self.assertTrue(dnsAnswer == "")
        first_network.remove()
        second_network.remove()
