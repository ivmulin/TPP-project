"""
Константы и функции, используемые в проекте.
"""

# Константы
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


def left_rotation(a: int, x: int) -> int:
    """
    Производит циклический сдвиг влево на x битов.
    """

    if x < 0:
        raise ValueError("x must be non-negative!")

    if a == 0:
        return 0

    mask = 2 ** (BYTE * sizeof(a)) - 1
    return mask & ((a << x) | (a >> (sizeof(a) * BYTE - x)))


def create_mask(n: int) -> int:
    """
    Создаёт маску из 1 длиной n в 16-ичной записи.
    Например, create_mask(4) = 0x1111.
    """

    return 2 ** n - 1
