#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        geoipdb_filename = 'geoipdb.txt'
        geoDB = GeoIPDB(filename=geoipdb_filename)

        # TODO: Load the firewall rules (from rule_filename) here.
        rule_filename = config['rule']
        self.rules = Rules(filename=rule_filename, geoipdb=geoDB)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        result = self.rules.result_for_pkt(pkt)
        if result == RULE_RESULT_PASS:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)

"""
Importing from file
"""

class LineImporter(object):
    def import_filename(self, filename):
        with open(filename) as f:
            lines = f.readlines()
            # Get rid of newlines
            lines = [line.strip('\n') for line in lines]
            # Get rid of extra spaces
            lines = [' '.join(line.split()) for line in lines]
            # Store this
            self.lines = lines

"""
Rules
"""

RULE_TYPE_PIP = 'RULE_TYPE_PIP'
RULE_TYPE_DNS = 'RULE_TYPE_DNS'

RULE_PROTOCOL_DNS = 'dns'

RULE_VERDICT = 0
RULE_PROTOCOL = 1
RULE_EXTERNAL_IP = 2
RULE_EXTERNAL_PORT = 3
RULE_DOMAIN_NAME = 2

RULE_RESULT_PASS = 'pass'
RULE_RESULT_DROP = 'drop'

class Rule:
    def __init__(self, rule_line):
        # To get rid of multiple white spaces
        rule_line = ' '.join(rule_line.split())
        rule_comps = rule_line.split(" ")
        # Get the verdict
        self.verdict = rule_comps[RULE_VERDICT]
        # Get the protocol
        self.protocol = rule_comps[RULE_PROTOCOL]

        # Handle differently for dns / pip
        if self.protocol == RULE_PROTOCOL_DNS:
            self.type = RULE_TYPE_DNS
            self.domain_name = rule_comps[RULE_DOMAIN_NAME]
        else:
            self.type = RULE_TYPE_PIP
            self.external_ip = rule_comps[RULE_EXTERNAL_IP]
            self.external_port = rule_comps[RULE_EXTERNAL_PORT]

class Rules(LineImporter):

    def __init__(self, filename, geoipdb = None):
        self.geoipdb = geoipdb
        self.rules = []
        # Call the import function
        super(Rules, self).import_filename(filename)
        # Convert these line strings to a list of rules
        for line in self.lines:
            # Ignore empty lines
            if len(line) == 0:
                continue
            # Ignore comment lines
            if line[0] == '%':
                continue
            # Create the rule
            rule = Rule(rule_line=line)
            self.rules.append(rule)
        # Invert the list, since the last rules hold priority
        self.rules = self.rules[::-1]

    def result_for_pkt(self, pkt):
        return RULE_RESULT_DROP


"""
GeoIPDB
"""

GEOIPDB_STARTING_IP = 0
GEOIPDB_ENDING_IP = 1
GEOIPDB_COUNTRY_CODE = 2
GEOIPDB_CODE_NOT_FOUND = 'GEOIPDB_CODE_NOT_FOUND'

class GeoIPDB(LineImporter):

    def __init__(self, filename):
        # We will store the DB file using a list and dictionary
        self.list = []
        self.hash = {}

        # Call the import function
        super(GeoIPDB, self).import_filename(filename)
        # Convert these line strings to list and dictionary
        for line in self.lines:
            line_tuple = line.split(" ")
            self.list.append(line_tuple)
            country_code = line_tuple[GEOIPDB_COUNTRY_CODE]
            if country_code not in self.hash:
                self.hash[country_code] = []
            # Append lines
            self.hash[country_code].append(line_tuple)
        

    def compareIP(self, ip1, ip2):
        """
        Return 0 if ip1 == ip2
        Return -1 if ip1 < ip2
        Return +1 if ip1 > ip2
        """
        ip1_comps = [int(comp) for comp in ip1.split(".")]
        ip2_comps = [int(comp) for comp in ip2.split(".")]
        components = [0, 1, 2, 3]
        for component in components:
            if ip1_comps[component] != ip2_comps[component]:
                if ip1_comps[component] < ip2_comps[component]:
                    return -1
                else:
                    return 1
        return 0

    def country_code(self, target_ip):
        """
        Returns the country code of the target ip
        or GEOIPDB_CODE_NOT_FOUND if it is not contained in our database
        """
        if len(self.list) > 0:
            return self.binary_search_country_code(target_ip, 0, len(self.list) - 1)
        else:
            return GEOIPDB_CODE_NOT_FOUND

    def binary_search_country_code(self, target_ip, start, end):
        difference = end - start
        if difference < 0:
            # Out of order
            return GEOIPDB_CODE_NOT_FOUND

        center = difference/2 + start
        # Get the center ip addresses
        center_line = self.list[center]
        center_start_ip = center_line[GEOIPDB_STARTING_IP]
        center_end_ip = center_line[GEOIPDB_ENDING_IP]
        # Get the comparisons
        start_comp = self.compareIP(target_ip, center_start_ip)
        end_comp = self.compareIP(target_ip, center_end_ip)

        # If it's either edge, or between both
        if (start_comp == 0 or end_comp == 0 or (start_comp == 1 and end_comp == -1)):
            # Found it
            return center_line[GEOIPDB_COUNTRY_CODE]
        else:
            if start_comp == -1:
                # Go left
                return self.binary_search_country_code(target_ip, start, center - 1)
            else:
                # Go right
                return self.binary_search_country_code(target_ip, center + 1, end)


