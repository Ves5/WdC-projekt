# All ciphers here
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

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
        cipher = AES.new(key, mode, nonce=nonce, initial_value=counter)
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
        cipher = AES.new(key, mode, nonce=nonce, initial_value=counter)
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
        cipher = DES3.new(key, mode, nonce=nonce, initial_value=counter)
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
        cipher = DES3.new(key, mode, nonce=nonce, initial_value=counter)
    elif (mode == DES3.MODE_CBC or DES3.MODE_CFB or DES3.MODE_OFB) and iv is not None:
        cipher = DES3.new(key, mode, iv=iv)
    else:
        return None
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode('utf-8')
