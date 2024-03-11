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
        expectation = 0x4adacd6b0005ec28c0de5fee44cde945

        c = camellia(message, key)
        m = camellia(c, key, DECRYPT)

        self.assertEqual(m, message)
        self.assertEqual(c, expectation)
