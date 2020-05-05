# All ciphers here
from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# noinspection DuplicatedCode
def AES_encrypt(key: bytes, plaintext: str, mode: int, iv=None, nonce=None, counter=0):
    """
    Perform encryption using AES
    :param key: symmetric key for the encryption
    :param plaintext: text to be encrypted
    :param mode: AES.MODE_ECB/CCB/CFB/OFB/CTR
    :param iv: initialization vector(length of block) needed for some modes: CBC, CFB, OFB
    :param nonce: fixed nonce for CTR mode, length from range(1-15) - 15 is optimal according to pycryptodome
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


# noinspection DuplicatedCode,PyShadowingNames
def AES_decrypt(key: bytes, ciphertext: bytes, mode: int, iv=None, nonce=None, counter=0):
    """
    Perform decryption using AES
    :param key: symmetric key for the decryption
    :param ciphertext: cipher text
    :param mode: AES.MODE_ECB/CCB/CFB/OFB/CTR
    :param iv: initialization vector(length of block) needed for some modes: CBC, CFB, OFB
    :param nonce: fixed nonce for CTR mode, length from range(1-15) - 15 is optimal according to pycryptodome
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


class CustomAES:
    """
    Class to make AES encryption using different modes and with transparent parallelism
    """

    def __init__(self, key) -> None:
        """
        Initialize the class for AES encryption/decryption
        :param key: key for AES ECB block
        """
        self.__executor = ThreadPoolExecutor(max_workers=3)
        self.__cipher = AES.new(key, AES.MODE_ECB)  # used just as an encryption block
        self.__result = []  # place for results of workers

    def __EBC_encrypt_worker(self, plaintext, index) -> None:
        """
        Encrypt plaintext of length 16 and put in result list at index
        :param plaintext: block to be encrypted
        :param index: index for result
        """
        self.__result[index:index + AES.block_size] = self.__cipher.encrypt(plaintext)

    # noinspection PyShadowingNames
    def __EBC_decrypt_worker(self, ciphertext, index) -> None:
        """
        Decrypt ciphertext of length 16 and put in result list at index
        :param ciphertext: block to be decrypted
        :param index: index for result
        """
        self.__result[index:index + AES.block_size] = self.__cipher.decrypt(ciphertext)

    # noinspection DuplicatedCode
    def encrypt_EBC(self, plaintext: str) -> bytes:
        """
        Perform encryption using AES with transparent concurrency
        :param plaintext: text to be encrypted
        :return: ciphertext
        """
        plaintext = pad(bytes(plaintext, 'utf-8'), AES.block_size)
        status = []
        i = 0
        self.__result = []
        while i < len(plaintext):
            status.append(self.__executor.submit(self.__EBC_encrypt_worker, plaintext[i:i + 16], i))
            i += 16
        futures.wait(status)
        return bytes(self.__result)

    # noinspection DuplicatedCode,PyShadowingNames
    def decrypt_EBC(self, ciphertext: bytes) -> str:
        """
        Perform decryption using AES with transparent concurrency
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        status = []
        i = 0
        self.__result = []
        while i < len(ciphertext):
            status.append(self.__executor.submit(self.__EBC_decrypt_worker, ciphertext[i:i + 16], i))
            i += 16
        futures.wait(status)
        plaintext = unpad(bytes(self.__result), AES.block_size)
        return plaintext.decode('utf-8')


# key = get_random_bytes(16)
# iv = get_random_bytes(AES.block_size)
# nonce = get_random_bytes(int(AES.block_size/2))
# counter = 0
# ciphertext = AES_encrypt(key, "Zażółć", AES.MODE_CTR, nonce=nonce, counter=10)
# print(AES_decrypt(key, ciphertext, AES.MODE_CTR, nonce=nonce, counter=10))

temp = CustomAES(get_random_bytes(16))
ciphertext = temp.encrypt_EBC(
    "The examples above are classes and objects in their simplest form, and are not really useful in real life applications.")
print(temp.decrypt_EBC(ciphertext))
