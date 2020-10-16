from .test_dockerDNS import TestDockerDNSIPv4

from twisted.trial import runner, reporter
import unittest


def suite():
    suite = unittest.TestSuite()
    suite.addTest(TestDockerDNSIPv4('test_basic_dns_request'))
    suite.addTest(TestDockerDNSIPv4('test_docker_network'))
    return suite


if __name__ == "__main__":
    reporter = reporter.TreeReporter
    runner = runner.TrialRunner(reporter)
    runner.run(suite())
