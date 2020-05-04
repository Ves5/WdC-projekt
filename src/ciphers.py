# All ciphers here

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def AES_encrypt(key: bytes, plaintext: str, mode: int, iv=None, nonce=None, counter=0):
    """
    Perform encryption using AES
    :param key: symmetric key for the encryption
    :param plaintext: text to be encrypted
    :param mode: AES.MODE_ECB/CCB/CFB/OFB/CTR
    :param iv: initialization vector(length of block) needed for some modes: CBC, CFB, OFB
    :param nonce: fixed nonce for CTR mode, length equal to half of the block
    :param counter: inital value of counter, default is 0
    :return: cipher text
    """
    if (mode is AES.MODE_CBC or AES.MODE_CFB or AES.MODE_OFB) and iv is not None:
        cipher = AES.new(key, mode, iv=iv)
    elif mode is AES.MODE_ECB:
        cipher = AES.new(key, mode)
    elif mode is AES.MODE_CTR and nonce is not None:
        cipher = AES.new(key, mode, nonce=nonce, initial_value=counter)
    else:
        return None
    return cipher.encrypt(pad(bytes(plaintext, 'utf-8') , AES.block_size))

def AES_decrypt(key: bytes, ciphertext: bytes, mode: int, iv=None, nonce=None, counter=0):
    """
    Perform decryption using AES
    :param key: symmetric key for the decryption
    :param ciphertext: cipher text
    :param iv: initialization vector(length of block) needed for some modes: CBC, CFB, OFB
    :param nonce: fixed nonce for CTR mode, length equal to half of the block
    :param counter: inital value of counter, default is 0
    :return: plain text from cipher
    """
    if (mode is AES.MODE_CBC or AES.MODE_CFB or AES.MODE_OFB) and iv is not None:
        cipher = AES.new(key, mode, iv=iv)
    elif mode is AES.MODE_ECB:
        cipher = AES.new(key, mode)
    elif mode is AES.MODE_CTR and nonce is not None:
        cipher = AES.new(key, mode, nonce=nonce, initial_value=counter)
    else:
        return None
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

key = get_random_bytes(16)
iv = get_random_bytes(AES.block_size)
nonce = get_random_bytes(int(AES.block_size/2))
counter = 0
ciphertext = AES_encrypt(key, "Zażółć", AES.MODE_CTR, nonce=nonce, counter=10)
print(AES_decrypt(key, ciphertext, AES.MODE_CTR, nonce=nonce, counter=10))