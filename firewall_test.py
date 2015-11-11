import unittest
from firewall import *

class GeoIPDBTest(unittest.TestCase):
    def setUp(self):
        self.g = GeoIPDB(filename='geoipdb.txt')

    def test_basic(self):
        pass

    def test_compare_ip_equal(self):
        ips_to_test = ['5.53.0.0', '5.159.215.255', '87.239.95.255',
        '115.42.31.255', '192.190.31.255', '195.226.216.255', '212.101.255.255']

        for ip_to_test in ips_to_test:
            result = self.g.compareIP(ip_to_test, ip_to_test)
            self.assertEqual(0, result)

    def test_compare_ip_less(self):
        ip_less = '5.53.0.0'
        ips_to_test = ['5.159.215.255', '87.239.95.255',
        '115.42.31.255', '192.190.31.255', '195.226.216.255', '212.101.255.255']

        for ip_to_test in ips_to_test:
            result = self.g.compareIP(ip_less, ip_to_test)
            self.assertEqual(-1, result)

    def test_compare_ip_more(self):
        ip_more = '212.101.255.255'
        ips_to_test = ['5.53.0.0', '5.159.215.255', '87.239.95.255',
        '115.42.31.255', '192.190.31.255', '195.226.216.255']

        for ip_to_test in ips_to_test:
            result = self.g.compareIP(ip_more, ip_to_test)
            self.assertEqual(1, result)

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