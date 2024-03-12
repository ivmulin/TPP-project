"""
Вашъ карманный шифраторъ, живущiй въ терминалѣ.
"""
from utilities import ENCRYPT, DECRYPT

from ciphers import camellia

from cipher_modes.mgm import mgm_encrypt, mgm_decrypt
from cipher_modes.ofb import ofb

import gettext


IS_STRING = "*"
EXAMPLE = IS_STRING + "../README.md"

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
        "choices": encr_modes,
        "help": """
Опредѣляетъ, будетъ ли сообщенiе зашифровано али наоборотъ.
Мой выборъ палъ на %(default)s, но ваше превосходительство 
вольны выбирать изъ доступных:
""" + ", ".join(encr_modes) + "."
    },

    ("-v", "--via"):
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
        "help": """
Пассажъ либо опусъ, интересующiй вашу милость. Коли вашей 
свѣтлости угодно, дабы я въ любомъ случаѣ воспринялъ посланiе 
какъ строку, передъ нею стоитъ поставить """ + IS_STRING + \
" такимъ манером: " + EXAMPLE + "."
    },

    ("-o", "--output"):
    {
        "type": str,
        "help": ""

}


def translate(phrase: str) -> str:
    dictionary = DICT_EN_RU
    if phrase in dictionary:
        phrase = dictionary[phrase]
    return phrase
gettext.gettext = translate

import argparse
from os import path


DESCRIPTION = "Вашъ карманный шифраторъ, живущiй въ терминалѣ."
FINALE = "За симъ я, вашъ покорный слуга, откланяюсь..."

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description = DESCRIPTION,
        epilog = FINALE)

    for i in HELP_RU:
        parser.add_argument(*i, **(HELP_RU[i]))

    args = parser.parse_args() # запуск парсера

    is_file = "valid file" if path.isfile(args.message) else "just string"
    print("Mode:", args.encr_mode)
    print("Algo:", args.via)
    print("Message:", args.message, "->", is_file)

    mode = args.encr_mode
    via = args.via
    message = args.message

    if path.isfile(message):
        with open(message) as file:
            message = file.read()

    if mode in ("e", "encrypt"):
        if via == "camellia":
            cipher 

