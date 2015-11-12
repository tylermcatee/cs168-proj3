import unittest
from firewall import *
from BinaryPacket import *

empty_rules = 'test_rules/empty.conf'
block_all_rules = 'test_rules/no.conf'
external_ip_drop_rules = 'test_rules/external_ip_drop.conf'
external_ip_prefix_drop_rules = 'test_rules/external_ip_prefix_drop.conf'
conflicting_rules = 'test_rules/conflicting_rules.conf'
block_any_port = 'test_rules/block_any_port.conf'
block_single_port = 'test_rules/block_single_port.conf'
country_block_rules = 'test_rules/country_block.conf'
block_port_range_rules = 'test_rules/block_port_range.conf'

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
        rules = Rules(block_all_rules)
        binary_packet = BinaryPacket().get_tcp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_block_outgoing_any(self):
        rules = Rules(block_all_rules)
        binary_packet = BinaryPacket().get_tcp_packet()
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_drop_external_ip_incoming(self):
        rules = Rules(external_ip_drop_rules)

        binary_packet = BinaryPacket()
        binary_packet.source_ip = '128.32.244.17' # This should be blocked
        binary_packet = binary_packet.get_tcp_packet()

        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_drop_external_ip_outgoing(self):
        rules = Rules(external_ip_drop_rules)

        binary_packet = BinaryPacket()
        binary_packet.dest_ip = '128.32.244.17' # This should be blocked
        binary_packet = binary_packet.get_tcp_packet()

        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_drop_external_ip_prefix_incoming(self):
        rules = Rules(external_ip_prefix_drop_rules)

        binary_packet = BinaryPacket()

        # Test edge 1
        binary_packet.source_ip = '123.34.128.0' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test middle
        binary_packet.source_ip = '123.34.200.194' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test edge 2
        binary_packet.source_ip = '123.34.255.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_drop_external_ip_prefix_outgoing(self):
        rules = Rules(external_ip_prefix_drop_rules)

        binary_packet = BinaryPacket()

        # Test edge 1
        binary_packet.dest_ip = '123.34.128.0' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test middle
        binary_packet.dest_ip = '123.34.212.2' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test edge 2
        binary_packet.dest_ip = '123.34.255.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_conflicting_rules_incoming(self):
        rules = Rules(conflicting_rules)

        binary_packet = BinaryPacket()

        # Test edge 1
        binary_packet.source_ip = '123.34.128.0' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)
        # Test middle
        binary_packet.source_ip = '123.34.225.225' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)
        # Test edge 2
        binary_packet.source_ip = '123.34.255.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)
        # Now test targeted allowed IP
        binary_packet.source_ip = '123.34.220.255' # This should be ALLOWED
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

    def test_tcp_conflicting_rules_outgoing(self):
        rules = Rules(conflicting_rules)

        binary_packet = BinaryPacket()

        # Test edge 1
        binary_packet.dest_ip = '123.34.128.0' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)
        # Test middle
        binary_packet.dest_ip = '123.34.225.225' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)
        # Test edge 2
        binary_packet.dest_ip = '123.34.255.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)
        # Now test targeted allowed IP
        binary_packet.dest_ip = '123.34.220.255' # This should be ALLOWED
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

    # # # # #
    # Port  #
    # # # # #

    def test_tcp_block_any_port_incoming(self):
        rules = Rules(block_any_port)

        binary_packet = BinaryPacket()
        binary_packet.source_ip = '255.255.255.254' # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)
        binary_packet.source_ip = '255.255.255.255' # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_block_any_port_outgoing(self):
        rules = Rules(block_any_port)

        binary_packet = BinaryPacket()
        binary_packet.dest_ip = '255.255.255.254' # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)
        binary_packet.dest_ip = '255.255.255.255' # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_block_single_port_incoming(self):
        rules = Rules(block_single_port)

        binary_packet = BinaryPacket()

        binary_packet.tcp_source = 52 # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

        binary_packet.tcp_source = 53 # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_block_single_port_outgoing(self):
        rules = Rules(block_single_port)

        binary_packet = BinaryPacket()

        binary_packet.tcp_dest = 52 # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

        binary_packet.tcp_dest = 53 # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_block_port_range_incoming(self):
        rules = Rules(block_port_range_rules)

        binary_packet = BinaryPacket()
        port_unblocked_range = range(0, 1000) + range(2001, 3001)
        port_blocked_range = range(1000, 2001)

        for port in port_unblocked_range:
            binary_packet.tcp_source = port # The rule shouldn't apply here
            packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_PASS, result)

        for port in port_blocked_range:
            binary_packet.tcp_source = port # The rule should apply here
            packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_DROP, result)

    def test_tcp_block_port_range_outgoing(self):
        rules = Rules(block_port_range_rules)

        binary_packet = BinaryPacket()
        port_unblocked_range = range(0, 1000) + range(2001, 3001)
        port_blocked_range = range(1000, 2001)

        for port in port_unblocked_range:
            binary_packet.tcp_dest = port # The rule shouldn't apply here
            packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_PASS, result)

        for port in port_blocked_range:
            binary_packet.tcp_dest = port # The rule should apply here
            packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=None)
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
        rules = Rules(block_all_rules)
        binary_packet = BinaryPacket().get_udp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_block_outgoing_any(self):
        rules = Rules(block_all_rules)
        binary_packet = BinaryPacket().get_udp_packet()
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_drop_external_ip_incoming(self):
        rules = Rules(external_ip_drop_rules)

        binary_packet = BinaryPacket()
        binary_packet.source_ip = '128.32.244.17' # This should be blocked
        binary_packet = binary_packet.get_udp_packet()

        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_drop_external_ip_outgoing(self):
        rules = Rules(external_ip_drop_rules)

        binary_packet = BinaryPacket()
        binary_packet.dest_ip = '128.32.244.17' # This should be blocked
        binary_packet = binary_packet.get_udp_packet()

        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_drop_external_ip_prefix_incoming(self):
        rules = Rules(external_ip_prefix_drop_rules)

        binary_packet = BinaryPacket()

        # Test edge 1
        binary_packet.source_ip = '123.34.128.0' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test middle
        binary_packet.source_ip = '123.34.129.1' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test edge 2
        binary_packet.source_ip = '123.34.255.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_drop_external_ip_prefix_outgoing(self):
        rules = Rules(external_ip_prefix_drop_rules)

        binary_packet = BinaryPacket()

        # Test edge 1
        binary_packet.dest_ip = '123.34.128.0' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test middle
        binary_packet.dest_ip = '123.34.252.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test edge 2
        binary_packet.dest_ip = '123.34.255.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    # # # # #
    # Port  #
    # # # # #

    def test_udp_block_any_port_incoming(self):
        rules = Rules(block_any_port)

        binary_packet = BinaryPacket()
        binary_packet.source_ip = '255.255.255.254' # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)
        binary_packet.source_ip = '255.255.255.255' # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_block_any_port_outgoing(self):
        rules = Rules(block_any_port)

        binary_packet = BinaryPacket()
        binary_packet.dest_ip = '255.255.255.254' # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)
        binary_packet.dest_ip = '255.255.255.255' # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_block_single_port_incoming(self):
        rules = Rules(block_single_port)

        binary_packet = BinaryPacket()

        binary_packet.udp_source = 52 # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

        binary_packet.udp_source = 53 # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_block_single_port_outgoing(self):
        rules = Rules(block_single_port)

        binary_packet = BinaryPacket()

        binary_packet.udp_dest = 52 # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

        binary_packet.udp_dest = 53 # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_block_port_range_incoming(self):
        rules = Rules(block_port_range_rules)

        binary_packet = BinaryPacket()
        port_unblocked_range = range(0, 1000) + range(2001, 3001)
        port_blocked_range = range(1000, 2001)

        for port in port_unblocked_range:
            binary_packet.udp_source = port # The rule shouldn't apply here
            packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_PASS, result)

        for port in port_blocked_range:
            binary_packet.udp_source = port # The rule should apply here
            packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_udp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_DROP, result)

    def test_udp_block_port_range_outgoing(self):
        rules = Rules(block_port_range_rules)

        binary_packet = BinaryPacket()
        port_unblocked_range = range(0, 1000) + range(2001, 3001)
        port_blocked_range = range(1000, 2001)

        for port in port_unblocked_range:
            binary_packet.udp_dest = port # The rule shouldn't apply here
            packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_PASS, result)

        for port in port_blocked_range:
            binary_packet.udp_dest = port # The rule should apply here
            packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_udp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_DROP, result)

    """
    ICMP
    """

    def test_icmp_no_rules_incoming(self):
        rules = Rules(empty_rules)
        binary_packet = BinaryPacket().get_icmp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

    def test_icmp_no_rules_outgoing(self):
        rules = Rules(empty_rules)
        binary_packet = BinaryPacket().get_icmp_packet()
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

    def test_icmp_block_incoming_any(self):
        rules = Rules(block_all_rules)
        binary_packet = BinaryPacket().get_icmp_packet()
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_block_outgoing_any(self):
        rules = Rules(block_all_rules)
        binary_packet = BinaryPacket().get_icmp_packet()
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_drop_external_ip_incoming(self):
        rules = Rules(external_ip_drop_rules)

        binary_packet = BinaryPacket()
        binary_packet.source_ip = '128.32.244.17' # This should be blocked
        binary_packet = binary_packet.get_icmp_packet()

        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_drop_external_ip_outgoing(self):
        rules = Rules(external_ip_drop_rules)

        binary_packet = BinaryPacket()
        binary_packet.dest_ip = '128.32.244.17' # This should be blocked
        binary_packet = binary_packet.get_icmp_packet()

        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet, geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_drop_external_ip_prefix_incoming(self):
        rules = Rules(external_ip_prefix_drop_rules)

        binary_packet = BinaryPacket()

        # Test edge 1
        binary_packet.source_ip = '123.34.128.0' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test middle
        binary_packet.source_ip = '123.34.128.1' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test edge 2
        binary_packet.source_ip = '123.34.255.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_drop_external_ip_prefix_outgoing(self):
        rules = Rules(external_ip_prefix_drop_rules)

        binary_packet = BinaryPacket()

        # Test edge 1
        binary_packet.dest_ip = '123.34.128.0' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test middle
        binary_packet.dest_ip = '123.34.252.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

        # Test edge 2
        binary_packet.dest_ip = '123.34.255.255' # This should be blocked
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    # # # # #
    # Port  #
    # # # # #

    def test_icmp_block_any_port_incoming(self):
        rules = Rules(block_any_port)

        binary_packet = BinaryPacket()
        binary_packet.source_ip = '255.255.255.254' # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)
        binary_packet.source_ip = '255.255.255.255' # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_block_any_port_outgoing(self):
        rules = Rules(block_any_port)

        binary_packet = BinaryPacket()
        binary_packet.dest_ip = '255.255.255.254' # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)
        binary_packet.dest_ip = '255.255.255.255' # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_block_single_port_incoming(self):
        rules = Rules(block_single_port)

        binary_packet = BinaryPacket()

        binary_packet.icmp_type = 52 # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

        binary_packet.icmp_type = 53 # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_block_single_port_outgoing(self):
        rules = Rules(block_single_port)

        binary_packet = BinaryPacket()

        binary_packet.icmp_type = 52 # The rule shouldn't apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_PASS, result)

        binary_packet.icmp_type = 53 # The rule should apply here
        packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
        result = rules.result_for_pkt(packet)
        self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_block_port_range_incoming(self):
        rules = Rules(block_port_range_rules)

        binary_packet = BinaryPacket()
        port_unblocked_range = range(0, 100) + range(201, 256)
        port_blocked_range = range(100, 201)

        for port in port_unblocked_range:
            binary_packet.icmp_type = port # The rule shouldn't apply here
            packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_PASS, result)

        for port in port_blocked_range:
            binary_packet.icmp_type = port # The rule should apply here
            packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_DROP, result)

    def test_icmp_block_port_range_outgoing(self):
        rules = Rules(block_port_range_rules)

        binary_packet = BinaryPacket()
        port_unblocked_range = range(0, 100) + range(201, 256)
        port_blocked_range = range(100, 201)

        for port in port_unblocked_range:
            binary_packet.icmp_type = port # The rule shouldn't apply here
            packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_PASS, result)

        for port in port_blocked_range:
            binary_packet.icmp_type = port # The rule should apply here
            packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_icmp_packet(), geoDB=None)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_DROP, result)

class GeoDBIntegrationTests(unittest.TestCase):
    def setUp(self):
        # Use the actual one, we have tested this object
        # thoroughly below
        self.geoDB = GeoIPDB(filename='geoipdb.txt')

        self.US_ip_examples = [
            '3.0.0.0', '3.53.8.23', '3.103.8.36', '5.149.107.128',
            '5.149.107.173', '5.149.107.128', '103.244.144.0', '103.244.144.123',
            '103.244.144.255',
        ]

        self.Non_US_ip_examples = [
            '1.0.0.0', '1.0.0.123', '1.0.0.255', '223.255.255.0', '223.255.255.254',
            '223.255.255.255', '225.225.225.225', '91.209.51.0', '91.209.51.1', 
            '91.209.51.255',
        ]

    def test_tcp_block_incoming(self):
        rules = Rules(country_block_rules)
        binary_packet = BinaryPacket()

        for US_ip in self.US_ip_examples:
            binary_packet.source_ip = US_ip # This should be blocked
            packet = Packet(pkt_dir=PKT_DIR_INCOMING, pkt=binary_packet.get_tcp_packet(), geoDB=self.geoDB)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_DROP, result)

    def tcp_block_outgoing(self):
        rules = Rules(country_block_rules)
        binary_packet = BinaryPacket()

        for US_ip in self.US_ip_examples:
            binary_packet.dest_ip = US_ip # This should be blocked
            packet = Packet(pkt_dir=PKT_DIR_OUTGOING, pkt=binary_packet.get_tcp_packet(), geoDB=self.geoDB)
            result = rules.result_for_pkt(packet)
            self.assertEqual(RULE_RESULT_DROP, result)