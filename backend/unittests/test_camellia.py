"""
Юнит-тест для алгоритма Camellia.
"""

import unittest

from utilities import bitsize, DECRYPT
from ciphers.camellia import camellia


class TestEncryptionAlgorithms(unittest.TestCase):
    def test_camellia(self):
        """
        Проверка алгоритма Camellia.
        """
        
        key = 0x123456789abcdeffedcba9876543210
        message = 0x0123456789abcdeffedcba9876543210

        c, key, r_t = camellia(message, key)
        m, key, r_t = camellia(c, key, DECRYPT, r_t)

        self.assertEqual(m, message)
