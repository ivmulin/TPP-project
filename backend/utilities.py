"""
Всякие полезные вспомогательности.
"""

BYTE = 8

# Маски
MASK8 = 0xff
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
MASK128 = 0xffffffffffffffffffffffffffffffff

# Флаги шифрования
ENCRYPT = 0
DECRYPT = ~ENCRYPT


def log(x: int, n: int) -> int:
    """
    floor( log(x, n) )
    """
    if x < 0:
        raise ValueError(f"x > 0 !!! Passed {x}, however.")
    l = 0
    if x == 0:
        return 0
    while (x := x // n):
        l += 1
    return l


def sizeof(x: int | str) -> int:
    """
    Аналог sizeof в C.
    """
    if type(x) == int:
        return log(x, 256) + 1

    if type(x) == str:
        return len(x)

    raise ValueError("Functionality for %s is not implemented." % type(x))


def bitsize(x: int) -> int:
    """
    Длина слова в битах.
    """

    bits = 0
    while x:
        x >>= 1
        bits += 1
    return bits


# ===== Маски =====


def unit_mask(n: int) -> int:
    """
    Создаёт маску из 1 длиной n бит.
    Например, unit_mask(4) = 0b1111.
    """

    return (1 << n) - 1


def chess_mask(n: int) -> int:
    """
    Возвращает пару (L, R), где
    L = 0b11...100...0,
    R = 0b00...011...1.

    n - чётное число.
    """

    if n % 2:
        raise ValueError("n must be even. Passed %i." % n)

    g = n // 2
    left = unit_mask(g) << g
    right = unit_mask(n) ^ left
    return left, right


# ===== Сдвиги и выравнивание =====


def left_rotation(a: int, x: int) -> int:
    """
    Производит циклический сдвиг влево на x бит.
    """

    if x < 0:
        raise ValueError("x must be non-negative!")

    if a == 0:
        return a

    x %= bitsize(a)

    if a == 0:
        return 0

    mask = unit_mask(bitsize(a))
    return mask & ((a << x) | (a >> (bitsize(a) - x)))


def pad(x: any, n: int) -> int:
    """
    Делает x (|x| < n) длиною в n бит.
    """
    if bitsize(x) >= n:
        raise ValueError(f"bitsize({x}) is bigger than {n}.")

    return x << (n - bitsize(x))
