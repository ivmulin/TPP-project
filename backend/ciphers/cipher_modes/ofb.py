"""
Режим шифрования OFB.
"""

from utilities import *


def ofb(encr_method: callable, message: int, key: int,
        iv: int) -> int:
    """
    Шифрование в режиме OFB.

    Из-за симметричности операции ^ шифрование и расшифровывание
    происходят одинаково.

    Аргументы:
    encr_method -   алгоритм шифрования
    message     -   шифруемое сообщение
    key         -   ключ шифрования
    iv          -   вектор инициализации

    Возвращает:
    cipher      -   шифротекст
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

    mask = unit_mask(bits) << (remainder + bits * (n-1))
    cipher = 0

    for i in range(n):
        k = encr_method(k, key)
        block = message & mask
        cipher <<= bits

        cipher |= (k ^ block)

        if i != n-1:
            mask >>= bits
        else:
            mask >>= remainder
    
    return cipher
