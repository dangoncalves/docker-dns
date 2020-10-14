#!/usr/bin/env/python3

import unittest
import docker
import time
import os
import signal
from multiprocessing import Process
from dockerDNS import DockerDNS
from dnslib.dns import DNSRecord


def resolveDNS(query, server, port):
    q = DNSRecord.question(query)
    answer_paquet = q.send(server, port, tcp=False)
    a = DNSRecord.parse(answer_paquet)
    if len(a.rr) > 0:
        return str(a.rr[0].rdata)
    else:
        return ""


class TestDockerDNS(unittest.TestCase):

    def dockerDNSProcess(self):
        p = DockerDNS(port=35353,
                      listenAddress="127.0.0.1",
                      forwarders="8.8.8.8")
        p.start()
        p.clean()

    def setUp(self):
        self.dockerClient = docker.from_env()

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
        self.assertTrue(dnsAnswer.startswith("172.17"))

        # We wait again to ensure the DNS entry
        # was removed after container has stopped.
        time.sleep(2)
        dnsAnswer = resolveDNS("test.dockerdns.io", "127.0.0.1", 35353)
        self.assertTrue(dnsAnswer == "")
