#!/usr/bin/env/python3

import unittest
import docker
import time
from dnslib.dns import DNSRecord
# from dockerDNS import run


def resolveDNS(query, server, port):
    q = DNSRecord.question(query)
    answer_paquet = q.send(server, port, tcp=False)
    a = DNSRecord.parse(answer_paquet)
    if len(a.rr) > 0:
        return str(a.rr[0].rdata)
    else:
        return ""


class TestDockerDNS(unittest.TestCase):

    def setUp(self):
        self.dockerClient = docker.from_env()

        # FIXME: Tests should be autonomous.
        #
        # Server cannot be started at this time
        # because we have to stop it gracefully
        # and the run function does not support
        # that actually.
        #
        # By the way, this mean that we have to
        # start the server manually before starting
        # tests.
        # Keep in mind that we have to use the
        # port 35353 in order to start the server
        # as a regular user.
        # run(35353, "127.0.0.1", "8.8.8.8")

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
