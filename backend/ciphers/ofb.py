"""
Режим шифрования OFB.
"""

from common_traits import *
from camellia import camellia_encrypt


def ofb(encrypt: callable, message: int, key: int,\
        iv: int) -> int:
    """
    OFB.

    Из-за симметричности операции ^ шифрование и расшифровывание
    происходят одинаково.
    """
    
    # =====  Подготовка  =====

    bits = sizeof(iv) * BYTE # размер блоков
    bits_in_message = sizeof(message) * BYTE
    k = iv

    # Определяем количества полных блоков в сообщении
    n = bits_in_message // bits
    n = 1 if n == 0 else n

    remainder = bits_in_message % bits # длина неполного блока

    # =====  Шифрование  =====

    mask = create_mask(bits) << (remainder + bits * (n-1))
    cipher = 0

    for i in range(n):
        k = encrypt(k, key)
        block = message & mask
        cipher <<= bits

        cipher |= (k ^ block)

        if i != n-1:
            mask >>= bits
        else:
            mask >>= remainder
    
    return cipher

if __name__ == "__main__":
    pass
