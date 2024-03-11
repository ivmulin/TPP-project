"""
Юнит-тест для режимов шифрования.
"""

import unittest

from cipher_modes.ofb import ofb
from cipher_modes.mgm import mgm_encrypt, mgm_decrypt

from ciphers.camellia import camellia


class TestCipherModes(unittest.TestCase):
    def test_ofb_camellia(self):
        """
        Проверка шифрования в режиме OFB
        при помощи алгоритма Camellia.
        """

        iv = 0x80000000000000000000000000000000
        me = 0x10000000000000000000000000000000
        ke = 0x80000000000000000000000000000000

        cipher = ofb(camellia, me, ke, iv)          # шифровка
        decipher = ofb(camellia, cipher, ke, iv)    # расшифровка

        self.assertEqual(hex(decipher), hex(me))


    def test_mgm_camellia(self):
        """
        Проверка шифрования в режиме MGM
        при помощи алгоритма Camellia.
        """

        n = 128
        nonce = 0x6 << (n-4)
        message = (0x7 << (n-2)) | 1
        ass_data = 0xbfee5c7c5fe97718ed6bf376739259fa

        key = 0x80000000000000000000000000000000
        c, a_d, t, r, *_ = mgm_encrypt(camellia, nonce,
                                  message, ass_data, key)   # шифровка
        m, a = mgm_decrypt(camellia, nonce, c, ass_data,
                           key, t, r, *_)                   # расшифровка

        self.assertEqual(message, m)
