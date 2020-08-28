import re
import json
import base64
import hashlib

from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from cryptography.fernet import Fernet


# from Crypto.Util.Padding import pad, unpad

def dict_to_binary(the_dict):
    binary = ' '.join(format(ord(letter), 'b') for letter in json.dumps(the_dict))
    return binary


def binary_to_dict(the_binary):
    jsn = ''.join(chr(int(x, 2)) for x in the_binary.split())
    d = json.loads(jsn)
    return d


def generate_key():
    key = Fernet.generate_key()
    key = base64.urlsafe_b64encode(json.dumps(encrypt_aes(key.decode(), 'ToniGuapo6?')).encode())
    with open("secret.key", "ab") as key_file:
        key_file.write(key + b'\r\n')


# def generate_hash_password(password, power=14):
#     hash_and_salt = bcrypt.hashpw(password.encode(), bcrypt.gensalt(power))
#     with open("pass.key", "wb") as key_file:
#         key_file.write(hash_and_salt)
#
#
# def check_password(password):
#     hash_password = open("pass.key", "rb").read()
#     return bcrypt.checkpw(password.encode(), hash_password)


# ======================================================
def encrypt_aes(message, password):
    # AES-256 encryption
    # generate a random salt
    salt = get_random_bytes(AES.block_size)
    # use the Scrypt KDF to get a private key from the password
    m = 128 * 8 * (2 ** 17 + 2 + 2)
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 17, r=8, p=2, maxmem=m, dklen=32)
    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(message, 'utf-8'))
    encrypted_aes_dict = {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }
    return encrypted_aes_dict


def decrypt_aes(enc_dict, password):
    # AES-256 decryption
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    # generate the private key from the password and salt
    m = 128 * 8 * (2 ** 17 + 2 + 2)
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 17, r=8, p=2, maxmem=m, dklen=32)
    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    # decrypt the cipher text
    return cipher.decrypt_and_verify(cipher_text, tag).decode()


def encrypt_fernet(message, key):
    return Fernet(key).encrypt(message.encode())


def decrypt_fernet(enc_message, key):
    return Fernet(key).decrypt(enc_message)


def encrypt_password(plain_text, password, key):
    encrypted_dict = encrypt_aes(plain_text, password)
    encoded_encrypted_dict = base64.urlsafe_b64encode(json.dumps(encrypted_dict).encode()).decode()
    return encrypt_fernet(encoded_encrypted_dict, key)


def decrypt_password(enc_pass, password, key):
    encoded_enc_dict = decrypt_fernet(enc_pass, key)
    enc_dict = json.loads(base64.urlsafe_b64decode(encoded_enc_dict).decode())
    return decrypt_aes(enc_dict, password)


def decrypt_key(password, pos_key):
    encoded_key = open("secret.key", "rb").read().splitlines()[pos_key]
    key = json.loads(base64.urlsafe_b64decode(encoded_key).decode())
    return decrypt_aes(key, password)


def decrypt_js(text):
    key = b'Qa//Ze?Bf1g<s@"I-S6.=fg?'
    BLOCK_SIZE = 16

    encrypted = base64.b64decode(text)
    IV = encrypted[:BLOCK_SIZE]
    aes = AES.new(key, AES.MODE_CBC, IV)
    return re.sub(r'[^\x20-\x7e]', '', aes.decrypt(encrypted[BLOCK_SIZE:]).decode())


# key = open("secret.key", "rb").read().splitlines()[0]
# print(b'w'+
# print(decrypt_fernet(encrypt_fernet('toni', 2),2))
# message = 'toniguapo'
# for i in range(42, 123):
#     key = open("secret.key", "rb").read().splitlines()[0]
#     print(chr(i))
#     key = chr(i).encode() + key[1:]
#     print(key)
#     try:
#         f = Fernet(key)
#         print(f.decrypt(f.encrypt(message.encode())))
#     except:
#         print('Error: '+chr(i)+'  '+str(i) )
#     print('\n===================================\n')
# #
# for i in range(35):
#     key = decrypt_key('ToniGuapo6?', 0)
#     e = encrypt_fernet('MastoYdeta6?', key)
#     print(decrypt_fernet(e, key))
