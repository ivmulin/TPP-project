"""
Юнит-тест для режимов шифрования.
"""

import unittest
from ofb import ofb
from camellia import camellia_encrypt
# import mgm

class TestOFB(unittest.TestCase):
    def test_ofb_camellia(self):
        iv  = 0x80000000000000000000000000000000
        me  = 0x10000000000000000000000000000000
        ke  = 0x80000000000000000000000000000000
        expected_cipher = 0xbfee5c7c5fe97718ed6bf376739259fa
        
        cipher = ofb(camellia_encrypt, me, ke, iv)
        decipher = ofb(camellia_encrypt, cipher, ke, iv)

        self.assertEqual(cipher, expected_cipher)   # шифровка
        self.assertEqual(decipher, me)              # расшифровка
