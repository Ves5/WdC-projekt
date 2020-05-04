# All ciphers here
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def DES3_encrypt(key: bytes, plaintext: str, mode=DES3.MODE_ECB):
    """
    Encrypt text via 3DES algorithm
    :param key: key used for encryption
    :param plaintext: text to be encrypted
    :param mode: mode of 3DES (optional) (default ECB)
    :return: encrypted text
    """
    cipher = DES3.new(key, mode)
    return cipher.encrypt(pad(plaintext.encode('utf-8'), DES3.block_size))
    
def DES3_decrypt(key: bytes, ciphertext: str, mode=DES3.MODE_ECB):
    """
    Decrypt text via 3DES algorithm
    :param key: key used for encryption
    :param cyphertext: text to be encrypted
    :param mode: mode of 3DES (optional) (default=ECB)
    :return: decrypted text
    """
    cipher = DES3.new(key, mode)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode('utf-8')

#text = "text to be encrypted"
#rkey = get_random_bytes(24)

#print(text)
#encrypted = DES3_encrypt(rkey, text)
#print(encrypted)
#decrypted = DES3_decrypt(rkey, encrypted)
#print(decrypted)