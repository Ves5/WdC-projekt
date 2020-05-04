# All ciphers here

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def AES_encrypt(key: bytes, plaintext: str):
    """
    Perform encryption using AES
    :param key: symmetric key for the encryption
    :param plaintext: text to be encrypted
    :return: cipher text
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(bytes(plaintext, 'utf-8') , AES.block_size))

def AES_decrypt(key: bytes, ciphertext: bytes):
    """
    Perform decryption using AES
    :param key: symmetric key for the decryption
    :param ciphertext: cipher text
    :return: plain text from cipher
    """
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')