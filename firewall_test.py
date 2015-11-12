import unittest
from firewall import *
from BinaryPacket import *

empty_rules = 'test_rules/empty.conf'
no_tcp_rules = 'test_rules/no_tcp.conf'
no_udp_rules = 'test_rules/no_udp.conf'

class IntegrationTests(unittest.TestCase):
    """
    Seeing if I can figure out why my code isn't passing all of the autograder
    """

    """
    TCP
    """

    def test_tcp_no_rules_incoming(self):
        rules = Rules(empty_rules)
        binary_packet = BinaryPacket().get_tcp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

    def test_tcp_no_rules_outgoing(self):
        rules = Rules(empty_rules)
        binary_packet = BinaryPacket().get_tcp_packet()
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

    def test_tcp_block_incoming_any(self):
        rules = Rules(no_tcp_rules)
        binary_packet = BinaryPacket().get_tcp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_block_outgoing_any(self):
        rules = Rules(no_tcp_rules)
        binary_packet = BinaryPacket().get_tcp_packet()
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    """
    UDP
    """

    def test_udp_no_rules_incoming(self):
        rules = Rules(empty_rules)
        binary_packet = BinaryPacket().get_udp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

    def test_udp_no_rules_outgoing(self):
        rules = Rules(empty_rules)
        binary_packet = BinaryPacket().get_udp_packet()
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

    def test_udp_block_incoming_any(self):
        rules = Rules(no_udp_rules)
        binary_packet = BinaryPacket().get_udp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_block_outgoing_any(self):
        rules = Rules(no_udp_rules)
        binary_packet = BinaryPacket().get_udp_packet()
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)


class RuleTest(unittest.TestCase):
    """
    Manually make sure all the lines from the given rules.conf
    work correctly.
    """
    def test_1(self):
        r = Rule('drop icmp any any')
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('icmp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('any', r.external_port)

    def test_2(self):
        r = Rule('pass icmp any 0')
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('pass', r.verdict)
        self.assertEqual('icmp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('0', r.external_port)

    def test_3(self):
        r = Rule('pass icmp any 8')
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('pass', r.verdict)
        self.assertEqual('icmp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('8', r.external_port)

    def test_4(self):
        r = Rule('drop udp any any')
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('udp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('any', r.external_port)

    def test_5(self):
        r = Rule('pass udp 8.8.8.8 53')
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('pass', r.verdict)
        self.assertEqual('udp', r.protocol)
        self.assertEqual('8.8.8.8', r.external_ip)
        self.assertEqual('53', r.external_port)

    def test_6(self):
        r = Rule('drop tcp any any')
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('tcp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('any', r.external_port)

    def test_7(self):
        r = Rule('   pass tcp any   80  ')
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('pass', r.verdict)
        self.assertEqual('tcp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('80', r.external_port)

    def test_8(self):
        r = Rule('drop tcp au any  ')
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('tcp', r.protocol)
        self.assertEqual('au', r.external_ip)
        self.assertEqual('any', r.external_port)

    def test_9(self):
        r = Rule('drop dns   stanford.edu')
        self.assertEqual(RULE_TYPE_DNS, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('dns', r.protocol)
        self.assertEqual('stanford.edu', r.domain_name)

    def test_10(self):
        r = Rule('drop dns *.stanford.edu')
        self.assertEqual(RULE_TYPE_DNS, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('dns', r.protocol)
        self.assertEqual('*.stanford.edu', r.domain_name)

class RulesTest(unittest.TestCase):
    def setUp(self):
        self.rules = Rules(filename='rules.conf')

    def test_basic(self):
        pass

    def test_rule_count(self):
        self.assertEqual(10, self.rules.rules.__len__())

    def test_rules_are_inverted_in_list(self):
        r = self.rules.rules[9]
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('icmp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('any', r.external_port)

        r = self.rules.rules[8]
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('pass', r.verdict)
        self.assertEqual('icmp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('0', r.external_port)

        r = self.rules.rules[7]
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('pass', r.verdict)
        self.assertEqual('icmp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('8', r.external_port)

        r = self.rules.rules[6]
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('udp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('any', r.external_port)

        r = self.rules.rules[5]
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('pass', r.verdict)
        self.assertEqual('udp', r.protocol)
        self.assertEqual('8.8.8.8', r.external_ip)
        self.assertEqual('53', r.external_port)

        r = self.rules.rules[4]
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('tcp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('any', r.external_port)

        r = self.rules.rules[3]
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('pass', r.verdict)
        self.assertEqual('tcp', r.protocol)
        self.assertEqual('any', r.external_ip)
        self.assertEqual('80', r.external_port)

        r = self.rules.rules[2]
        self.assertEqual(RULE_TYPE_PIP, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('tcp', r.protocol)
        self.assertEqual('au', r.external_ip)
        self.assertEqual('any', r.external_port)

        r = self.rules.rules[1]
        self.assertEqual(RULE_TYPE_DNS, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('dns', r.protocol)
        self.assertEqual('stanford.edu', r.domain_name)

        r = self.rules.rules[0]
        self.assertEqual(RULE_TYPE_DNS, r.type)
        self.assertEqual('drop', r.verdict)
        self.assertEqual('dns', r.protocol)
        self.assertEqual('*.stanford.edu', r.domain_name)

class IPHelperFunctionsTest(unittest.TestCase):

    def test_compare_ip_equal(self):
        ips_to_test = ['5.53.0.0', '5.159.215.255', '87.239.95.255',
        '115.42.31.255', '192.190.31.255', '195.226.216.255', '212.101.255.255']

        for ip_to_test in ips_to_test:
            result = compareIP(ip_to_test, ip_to_test)
            self.assertEqual(0, result)

    def test_compare_ip_less(self):
        ip_less = '5.53.0.0'
        ips_to_test = ['5.159.215.255', '87.239.95.255',
        '115.42.31.255', '192.190.31.255', '195.226.216.255', '212.101.255.255']

        for ip_to_test in ips_to_test:
            result = compareIP(ip_less, ip_to_test)
            self.assertEqual(-1, result)

    def test_compare_ip_more(self):
        ip_more = '212.101.255.255'
        ips_to_test = ['5.53.0.0', '5.159.215.255', '87.239.95.255',
        '115.42.31.255', '192.190.31.255', '195.226.216.255']

        for ip_to_test in ips_to_test:
            result = compareIP(ip_more, ip_to_test)
            self.assertEqual(1, result)

    def test_ip_prefix_to_range_1(self):
        ip_range = ip_prefix_to_range('192.168.0.0/24')
        self.assertEqual('192.168.0.0', ip_range[0])
        self.assertEqual('192.168.0.255', ip_range[1])

    def test_ip_prefix_to_range_2(self):
        ip_range = ip_prefix_to_range('192.168.0.0/30')
        self.assertEqual('192.168.0.0', ip_range[0])
        self.assertEqual('192.168.0.3', ip_range[1])

    def test_ip_prefix_to_range_3(self):
        ip_range = ip_prefix_to_range('192.168.0.0/16')
        self.assertEqual('192.168.0.0', ip_range[0])
        self.assertEqual('192.168.255.255', ip_range[1])


class GeoIPDBTest(unittest.TestCase):
    def setUp(self):
        self.g = GeoIPDB(filename='geoipdb.txt')

    def test_basic(self):
        pass

    def test_get_country_code_first(self):
        code = self.g.country_code('1.0.0.200')
        self.assertEqual(code, 'AU')

    def test_get_country_code_last(self):
        code = self.g.country_code('223.255.255.200')
        self.assertEqual(code, 'AU')

    def test_get_country_code_middle_1(self):
        code = self.g.country_code('194.205.179.20')
        self.assertEqual(code, 'EU')

    def test_get_country_code_middle_2(self):
        code = self.g.country_code('194.205.179.20')
        self.assertEqual(code, 'EU')

    def test_get_country_code_middle_3(self):
        code = self.g.country_code('194.205.179.20')
        self.assertEqual(code, 'EU')

    def test_get_country_code_middle_4(self):
        code = self.g.country_code('194.205.179.20')
        self.assertEqual(code, 'EU')

    def test_get_country_code_out_of_range(self):
        code = self.g.country_code('255.255.255.255')
        self.assertEqual(GEOIPDB_CODE_NOT_FOUND, code)