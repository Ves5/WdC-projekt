# All ciphers here
from Crypto.Cipher import DES3, AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import Salsa20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def AES_encrypt(key: bytes, plaintext: str, mode: int, iv=None, nonce=None, counter=0):
    """
    Perform encryption using AES
    :param key: symmetric key for the encryption
    :param plaintext: text to be encrypted
    :param mode: AES.MODE_ECB/CCB/CFB/OFB/CTR
    :param iv: initialization vector(length of block) needed for some modes: CBC, CFB, OFB
    :param nonce: fixed nonce for CTR mode, length from range(1-15)
    :param counter: initial value of counter, default is 0
    :return: cipher text
    """
    if (mode is AES.MODE_CBC or AES.MODE_CFB or AES.MODE_OFB) and iv is not None:
        cipher = AES.new(key, mode, iv=iv)
    elif mode is AES.MODE_ECB:
        cipher = AES.new(key, mode)
    elif mode is AES.MODE_CTR and nonce is not None:
        cipher = AES.new(key, mode, nonce=nonce, counter=Counter.new(nbits=len(nonce), initial_value=counter))
    else:
        return None
    return cipher.encrypt(pad(bytes(plaintext, 'utf-8'), AES.block_size))


def AES_decrypt(key: bytes, ciphertext: bytes, mode: int, iv=None, nonce=None, counter=0):
    """
    Perform decryption using AES
    :param key: symmetric key for the decryption
    :param ciphertext: cipher text
    :param mode: AES.MODE_ECB/CCB/CFB/OFB/CTR
    :param iv: initialization vector(length of block) needed for some modes: CBC, CFB, OFB
    :param nonce: fixed nonce for CTR mode, length from range(1-15)
    :param counter: initial value of counter, default is 0
    :return: plain text from cipher
    """
    if (mode is AES.MODE_CBC or AES.MODE_CFB or AES.MODE_OFB) and iv is not None:
        cipher = AES.new(key, mode, iv=iv)
    elif mode is AES.MODE_ECB:
        cipher = AES.new(key, mode)
    elif mode is AES.MODE_CTR and nonce is not None:
        cipher = AES.new(key, mode, nonce=nonce, counter=Counter.new(nbits=len(nonce), initial_value=counter))
    else:
        return None
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

def DES3_encrypt(key: bytes, plaintext: str, mode=DES3.MODE_ECB, iv=None, nonce=None, counter=0):
    """
    Encrypt text via 3DES algorithm from PyCryptodome
    :param key: key used for encryption
    :param plaintext: text to be encrypted
    :param mode: mode of DES3 (default ECB) [DES3.MODE_ECB/CTR/CBC/CFB/OFB]
    :param iv: initialization vector (8 bytes long)
    :param nonce: nonce for CTR mode (length 0-7)
    :param counter: counter init value (default 0)
    :return: encrypted text
    """
    if mode == DES3.MODE_ECB:
        cipher = DES3.new(key, mode)
    elif mode == DES3.MODE_CTR and nonce is not None:
        cipher = DES3.new(key, mode, nonce=nonce, counter=Counter.new(nbits=len(nonce), initial_value=counter))
    elif mode == DES3.MODE_CBC or DES3.MODE_CFB or DES3.MODE_OFB and iv is not None:
        cipher = DES3.new(key, mode, iv=iv)
    else:
        return None
    return cipher.encrypt(pad(plaintext.encode('utf-8'), DES3.block_size))
    
def DES3_decrypt(key: bytes, ciphertext: bytes, mode=DES3.MODE_ECB, iv=None, nonce=None, counter=0):
    """
    Decrypt text via 3DES algorithm from PyCryptodome
    :param key: key used for encryption
    :param cyphertext: text to be encrypted
    :param mode: mode of DES3 (default ECB) [DES3.MODE_ECB/CTR/CBC/CFB/OFB]
    :param iv: initialization vector (8 bytes long)
    :param nonce: nonce for CTR mode (length 0-7)
    :param counter: counter init value (default 0)
    :return: decrypted text
    """
    if mode == DES3.MODE_ECB:
        cipher = DES3.new(key, mode)
    elif mode == DES3.MODE_CTR and nonce is not None:
        cipher = DES3.new(key, mode, nonce=nonce, counter=Counter.new(nbits=len(nonce), initial_value=counter))
    elif (mode == DES3.MODE_CBC or DES3.MODE_CFB or DES3.MODE_OFB) and iv is not None:
        cipher = DES3.new(key, mode, iv=iv)
    else:
        return None
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode('utf-8')

def encrypt_Salsa20(plaintext, secret):
    bytetext = bytes(plaintext, 'utf-8')
    cipher = Salsa20.new(key=secret)
    msg = cipher.nonce + cipher.encrypt(bytetext)
    return msg

def decrypt_Salsa20(msg, secret):
    msg_nonce = msg[:8]
    ciphertext = msg[8:]
    cipher = Salsa20.new(key=secret, nonce=msg_nonce)
    plaintext = cipher.decrypt(ciphertext)
    return str(plaintext, 'utf-8')

def get_key_pair():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return public_key, private_key

def encrypt_RSA(plaintext, public_key):
    bytetext = bytes(plaintext, 'utf-8')
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encoded_data = cipher_rsa.encrypt(bytetext)
    return encoded_data

def decrypt_RSA(encoded_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    bytetext = cipher_rsa.decrypt(encoded_data)
    return str(bytetext, 'utf-8')