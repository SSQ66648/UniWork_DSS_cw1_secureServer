import string
import random
import winreg
import hashlib
from flask import session
from helpers import database as db

CIPHER_KEY_REG_PATH = r"SOFTWARE\dss-forum"
CIPHER_KEY_REG_NAME = 'caesar_cipher_key'

# encoding function character list
html_escape_table = {
    # "top five escape requirements" -based in xml escaping
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    # additional escape characters (potentially not needed but reduces unforeseen risk)
    "@": "&commat;",
    "+": "&plus;",
    "-": "&minus;",
    "∗": "&lowast;",
    "×": "&times;",
    "÷": "&divide;",
    "=": "&equals;",
    "≠": "&ne;",
    "!": "&excl;",
    "?": "&quest;",
    "–": "&ndash;",
    "—": "&mdash;",
    "‹": "&lsaquo;",
    "›": "&rsaquo;",
    "«": "&laquo;",
    "»": "&raquo;",
    "ƒ": "&fnof;",
    "%": "&percnt;",
    "∃": "&exist;",
    "∄": "&nexist;",
    "∅": "&empty;",
    "∈": "&isin;",
    "∉": "&notin;",
    "∋": "&ni;",
    "∌": "&notni;",
    "∝": "&prop;",
    "∞": "&infin;",
    "∣": "&mid;",
    "∤": "&nmid;",
    "∧": "&and;",
    "∨": "&or;",
    "∩": "&cap;",
    "∪": "&cup;",
    "∼": "&sim;",
    "≤": "&le;",
    "≥": "&ge;",
    "⊂": "&sub;",
    "⊃": "&sup;",
    "⊄": "&nsub;",
    "⊅": "&nsup;",
    "⋕": "&epar;",
    "(": "&lpar;",
    ")": "&rpar;",
    "*": "&ast;",
    ",": "&comma;",
    ".": "&period;",
    "/": "&sol;",
    ":": "&colon;",
    ";": "&semi;",
    "\\": "&bsol;",
    "[": "&lbrack;",
    "]": "&rbrack;",
    "^": "&Hat;",
    "_": "&lowbar;",
    "`": "&grave;",
    "{": "&lbrace;",
    "}": "&rbrace;",
    "|": "&vert;",
    "~": "&tilde;",
    "´": "&acute;",
    "·": "&middot;",
    "‘": "&lsquo;",
    "’": "&rsquo;",
    "“": "&ldquo;",
    "”": "&rdquo;",
    "$": "&dollar;",
}


# return the encryption cipher key which is stored in the windows registry
def get_cipher_key():
    try:
        # open registry key
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CIPHER_KEY_REG_PATH, 0,
                                      winreg.KEY_READ)
        # read the registry pepper value
        value, regtype = winreg.QueryValueEx(registry_key, CIPHER_KEY_REG_NAME)

        # close registry key and return value
        winreg.CloseKey(registry_key)
        return int(value)
    except WindowsError:
        # return nothing on error
        return None


# encoding escape function
def html_encode(text):
    # replace all html special character with encoded versions
    if isinstance(text, str):
        return "".join(html_escape_table.get(c, c) for c in text)
    return text


# encoding escape function
def html_decode(text):
    # replace all encoded html characters with original
    if isinstance(text, str):
        for key in html_escape_table.keys():
            text = text.replace(html_escape_table[key], key)
    return text


# database query escaping function (does not iterate over numbers)
def escape_db(dataset):
    for row in dataset:
        for column in row:
            row[column] = html_encode(row[column])
    return dataset


def generate_random_string(length, charset=[]):
    # define default charset of all characters if none provided
    if not charset:
        charset = [string.ascii_letters, string.digits, string.punctuation]

    # get valid characters for random string (i.e. lowercase and uppercase letters + numbers)
    valid_characters = ''
    for chars in charset:
        valid_characters += chars

    # return a random string of the specified length using the charset provided
    return ''.join(random.choice(valid_characters) for i in range(length))


# generate random string for CSRF forms
def generate_csrf():
    session['csrf_token'] = generate_random_string(64, [string.ascii_letters, string.digits])
    return session['csrf_token']


# basic encryption algorithm: pass mode to encrypt or decrypt using same method
def caesar_cipher(mode, input_text):
    # construct single cipher alphabet
    # (to reduce obvious upper/lowercase/number pattern identification)
    # (array version is easier to use/debug than previous)
    caesar_alphabet = [' ', '!', '\"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2',
                       '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E',
                       'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                       'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
                       'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', ',', '}',
                       '~']

    output_string = ''
    key_value = get_cipher_key()

    for character in range(len(input_text)):
        # get char
        current_char = input_text[character]
        if current_char in caesar_alphabet:
            alphabet_index = caesar_alphabet.index(current_char)
            # either encrypt or decrypt by mode (value converted to lowercase to prevent case-mismatches)
            if mode.lower() == "encrypt":
                shifted_index = (alphabet_index + key_value) % len(caesar_alphabet)
            elif mode.lower() == "decrypt":
                shifted_index = (alphabet_index - key_value) % len(caesar_alphabet)
            else:
                print("caesar_cipher: ERROR: passed MODE not recognised. please enter either ENCRYPT or DECRYPT")
                return
            shifted_char = caesar_alphabet[shifted_index]
        else:
            # symbol not found in in 'basic latin' unicode characters: copy character verbatim
            shifted_char = character

        # append to return string
        output_string += str(shifted_char)

    return output_string


# return http protocol, used for hard
def get_url_protocol():
    return 'http://'


def hash_password(password, salt):
    return hashlib.sha512(
        (password + salt + db.get_password_pepper()).encode('utf-8')
    ).hexdigest()


def hash_encrypt_password(password, salt):
    return caesar_cipher("encrypt", hash_password(password, salt))
