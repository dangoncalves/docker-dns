from .test_dockerDNS import TestDockerDNSIPv4NoHealthCheck
from .test_dockerDNS import TestDockerDNSIPv6NoHealthCheck
from .test_dockerDNS import TestDockerDNSIPv4HealthCheck
from .test_dockerDNS import TestDockerDNSIPv6HealthCheck

from twisted.trial import runner, reporter
import unittest


def suite():
    suite = unittest.TestSuite()
    suite.addTest(TestDockerDNSIPv4NoHealthCheck('test_basic_dns_request'))
    suite.addTest(TestDockerDNSIPv4NoHealthCheck('test_docker_network'))
    suite.addTest(TestDockerDNSIPv6NoHealthCheck('test_basic_dns_request'))
    suite.addTest(TestDockerDNSIPv6NoHealthCheck('test_docker_network'))
    suite.addTest(TestDockerDNSIPv4HealthCheck('test_basic_dns_request'))
    suite.addTest(TestDockerDNSIPv4HealthCheck('test_docker_network'))
    suite.addTest(TestDockerDNSIPv6HealthCheck('test_basic_dns_request'))
    suite.addTest(TestDockerDNSIPv6HealthCheck('test_docker_network'))
    return suite


if __name__ == "__main__":
    reporter = reporter.TreeReporter
    runner = runner.TrialRunner(reporter)
    runner.run(suite())
