
import unittest
import pytest
from IPAdress import IP

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

if __name__ == '__main__':
    unittest.main()
