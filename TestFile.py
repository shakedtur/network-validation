
import unittest
import pytest
from IPAdress import IP
from Validation import Validator
from Policy import Policy
from IP_Packet import IP_Packet_Ports

# class MyTestCase(unittest.TestCase):
#     def test_something(self):
#         self.assertEqual(True, False)

class TestIP(unittest.TestCase):

    def test_ip_equality(self):
        ip1 = IP(192,168,1,1)
        ip2 = IP(192,168,1,1)
        ip3 = IP(192,168,1,2)
        self.assertEqual(ip1, ip2)
        self.assertNotEqual(ip1, ip3)


    def test_ip_equality_with_non_ip(self):
        ip = IP(192,168,1,1)
        self.assertNotEqual(ip, "192.168.1.1")


class TestValidator(unittest.TestCase):

    def setUp(self):
        self.packet_ip_block_1 = IP_Packet_Ports(1, "10.1.1.1", "10.0.0.7", "TCP", 80, 443)
        self.packet_ip_block_2 = IP_Packet_Ports(2, "10.0.0.1", "10.1.1.1", "UDP", 80, 80)

        self.blocked_sources=["10.1.1.1", "172.16.0.9"]
        self.allowed_routes = [
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.5",
                "protocol": "TCP",
                "dst_port": 443
            }
        ]
        self.policy = Policy(self.blocked_sources,self.allowed_routes)
        self.packet_list = [self.packet_ip_block_1, self.packet_ip_block_2]
        self.validator = Validator(self.policy, self.packet_list)

    def test_block_ip_check(self):
        result_block = self.validator.packet_blocked_check(self.packet_ip_block_1)
        result_allow = self.validator.packet_blocked_check(self.packet_ip_block_2)
        self.assertTrue(result_block)
        self.assertFalse(result_allow)

    def test_packet_allow_check(self):

        packet = IP_Packet_Ports(1, "192.168.1.1", "10.0.0.5", "TCP", 12345, 443)
        validator = Validator(self.policy, [packet])
        result = validator.packet_allow_check(packet)

        self.assertTrue(result)
        self.assertEqual(packet.tag, "Valid")

    def test_packet_not_allowed(self):

        validator = Validator(self.policy, [])

        # 1.change source_ip
        packet_wrong_src = IP_Packet_Ports(2, "192.168.1.99", "10.0.0.5", "TCP", 12345, 443)
        result = validator.packet_allow_check(packet_wrong_src)
        self.assertFalse(result)
        self.assertEqual(packet_wrong_src.tag, "Invalid")

        # 2.change destination_ip
        packet_wrong_dst = IP_Packet_Ports(3, "192.168.1.1", "10.0.0.99", "TCP", 12345, 443)
        result = validator.packet_allow_check(packet_wrong_dst)
        self.assertFalse(result)
        self.assertEqual(packet_wrong_dst.tag, "Invalid")

        # 3.change protocol
        packet_wrong_proto = IP_Packet_Ports(4, "192.168.1.1", "10.0.0.5", "UDP", 12345, 443)
        result = validator.packet_allow_check(packet_wrong_proto)
        self.assertFalse(result)
        self.assertEqual(packet_wrong_proto.tag, "Invalid")

        # 4.change destination_port
        packet_wrong_port = IP_Packet_Ports(5, "192.168.1.1", "10.0.0.5", "TCP", 12345, 80)
        result = validator.packet_allow_check(packet_wrong_port)
        self.assertFalse(result)
        self.assertEqual(packet_wrong_port.tag, "Invalid")



if __name__ == '__main__':
    unittest.main()
