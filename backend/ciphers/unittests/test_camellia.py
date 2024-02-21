"""
Юнит-тест для алгоритма Camellia.
"""

import unittest
import camellia


class TestCamellia(unittest.TestCase):
    def test_camellia_encrypt(self):
        key = 0x0123456789abcdeffedcba9876543210
        message = 0x0123456789abcdeffedcba9876543210
        expectation = 0x67673138549669730857065648eabe43

        self.assertEqual(camellia.camellia_encrypt(message, key), expectation)
