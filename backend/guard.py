"""
Вашъ карманный шифраторъ, живущiй въ терминалѣ.
"""

from ciphers import camellia

from cipher_modes.mgm import mgm_encrypt, mgm_decrypt
from cipher_modes.ofb import ofb

import gettext


encr_modes = [
    "e", "encrypt",
    "d", "decrypt"
]

algorithms = [
    "camellia",
    "ofb-camellia",
    "mgm-camellia",
]

DICT_EN_RU = {
    "usage": "команда",
    "positional arguments": "arguments positionnels",
    "options": "факультативные параметры",
    "show this help message and exit": "Показать сiе сообщенiе да откланяться."
}

HELP_RU = {
    ("encr_mode", ): 
    {
        "default": "encrypt",
        "help": """
Опредѣляетъ, будетъ ли сообщенiе зашифровано али наоборотъ.
Мой выборъ палъ на %(default)s, но ваше превосходительство 
вольны выбирать изъ доступных:
""" + ", ".join(encr_modes) + "."
    },

    ("-a", "--algorithm"):
    {
        "type": str,
        "default": algorithms[0],
        "choices": algorithms,
        "metavar": "МЕТОДЪ",
        "help": """
Методъ шифрованiя, коимъ вашему превосходительству
угодно будетъ воспользоваться. На сей часъ въ наличiи """ + 
", ".join(algorithms) + \
". За неимѣнием вашей свѣтлости я выбралъ %(default)s."
    },
    
    ("message", ):
    {
        "help": "Пассажъ либо опусъ, интересующiй вашу милость."
    },
}


def translate(phrase: str) -> str:
    dictionary = DICT_EN_RU
    if phrase in dictionary:
        phrase = dictionary[phrase]
    return phrase
gettext.gettext = translate

import argparse


DESCRIPTION = "Вашъ карманный шифраторъ, живущiй въ терминалѣ."
FINALE = "За симъ я, вашъ покорный слуга, откланяюсь..."

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = DESCRIPTION,
        epilog = FINALE)

    for i in HELP_RU:
        parser.add_argument(*i, **(HELP_RU[i]))

    args = parser.parse_args() # запуск парсера
