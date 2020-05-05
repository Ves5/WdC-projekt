# All ciphers here
from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor
from typing import List

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


# noinspection DuplicatedCode,PyShadowingNames
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


# noinspection DuplicatedCode, PyShadowingNames
class CustomModes:
    """
    Class to make block encryption using different modes and with transparent parallelism.
    Default is AES
    """
    __result: List

    def __init__(self, key: bytes, algorithm="AES") -> None:
        """
        Initialize the class for AES encryption/decryption
        :param key: key for AES ECB block
        :param algorithm: algorithm to use: AES/..; default is AES
        """

        self.__executor = ThreadPoolExecutor(max_workers=3)
        self.__result = []  # place for results of workers

        # initialize chosen algorithm
        if algorithm == "AES":
            self.__cipher = AES.new(key, AES.MODE_ECB)  # used just as an encryption block
            self.__block_size = AES.block_size
        # place for initialization for other algorithms - remember about updating init DocString

        self.iv = None  # initialization vector needed for some modes

    @staticmethod
    def __byte_xor(ba1, ba2):
        """
        Perform xor on two byte arrays
        """
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    def __EBC_encrypt_worker(self, plaintext, index) -> None:
        """
        Encrypt plaintext of one block and put in result list at index
        :param plaintext: block to be encrypted
        :param index: index for result
        """
        self.__result[index:index + self.__block_size] = self.__cipher.encrypt(plaintext)

    def __EBC_decrypt_worker(self, ciphertext, index) -> None:
        """
        Decrypt ciphertext of one block and put in result list at index
        :param ciphertext: block to be decrypted
        :param index: index for result
        """
        self.__result[index:index + self.__block_size] = self.__cipher.decrypt(ciphertext)

    def encrypt_EBC(self, plaintext: str) -> bytes:
        """
        Perform EBC encryption using AES with transparent concurrency
        :param plaintext: text to be encrypted
        :return: ciphertext
        """
        plaintext = pad(bytes(plaintext, 'utf-8'), self.__block_size)
        status = []
        i = 0
        self.__result = [None] * len(plaintext)

        # place jobs for executor for single blocks
        while i < len(plaintext):
            status.append(self.__executor.submit(self.__EBC_encrypt_worker, plaintext[i:i + 16], i))
            i += 16

        # wait for all jobs to be completed
        futures.wait(status)
        return bytes(self.__result)

    def decrypt_EBC(self, ciphertext: bytes) -> str:
        """
        Perform EBC decryption using AES with transparent concurrency
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        status = []
        i = 0
        self.__result = [None] * len(ciphertext)

        # place jobs for executor for single blocks
        while i < len(ciphertext):
            status.append(self.__executor.submit(self.__EBC_decrypt_worker, ciphertext[i:i + 16], i))
            i += 16

        # wait for all jobs to be completed
        futures.wait(status)
        plaintext = unpad(bytes(self.__result), self.__block_size)
        return plaintext.decode('utf-8')

    def encrypt_CBC(self, plaintext: str) -> bytes:
        """
        Perform CBC encryption using AES; initialization vector must be set
        :param plaintext: text to be encrypted
        :return: ciphertext
        """
        if self.iv is not None:
            plaintext = pad(bytes(plaintext, 'utf-8'), self.__block_size)
            self.__result = [None] * len(plaintext)

            # first block
            temp = self.__byte_xor(plaintext[0:self.__block_size], self.iv)
            self.__result[0:self.__block_size] = self.__cipher.encrypt(temp)

            # all next blocks
            i = 16
            while i < len(plaintext):
                temp = self.__byte_xor(plaintext[i:i + self.__block_size], self.__result[i - self.__block_size:i])
                self.__result[i:i + self.__block_size] = self.__cipher.encrypt(temp)
                i += 16

            return bytes(self.__result)

    def __CBC_decrypt_worker(self, ciphertext, previous, index) -> None:
        """
        Decrypt ciphertext of length 16 and put in result list at index
        :param ciphertext: block to be decrypted
        :param index: index for result
        """
        self.__result[index:index + self.__block_size] = self.__byte_xor(self.__cipher.decrypt(ciphertext), previous)

    def decrypt_CBC(self, ciphertext: bytes) -> str:
        """
        Perform EBC decryption using AES with transparent concurrency; initialization vector must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """

        if self.iv is not None:
            self.__result = [None] * len(ciphertext)

            # first block into jobs
            status = [self.__executor.submit(self.__CBC_decrypt_worker, ciphertext[0:self.__block_size], self.iv, 0)]

            # place all next blocks in jobs queue
            i = 16
            while i < len(ciphertext):
                status.append(self.__executor.submit(self.__CBC_decrypt_worker, ciphertext[i:i + self.__block_size],
                                                     ciphertext[i - self.__block_size:i], i))
                i += 16

            # wait for all jobs to be completed
            futures.wait(status)
            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')

    def decrypt_CBC_slow(self, ciphertext: bytes) -> str:
        """
        Perform EBC decryption using AES without concurrency; initialization vector must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        if self.iv is not None:
            self.__result = [None] * len(ciphertext)

            # first block
            temp = self.__cipher.decrypt(ciphertext[0:self.__block_size])
            self.__result[0:self.__block_size] = self.__byte_xor(temp, self.iv)

            # all next blocks
            i = 16
            while i < len(ciphertext):
                temp = self.__cipher.decrypt(ciphertext[i:i + self.__block_size])
                self.__result[i:i + self.__block_size] = self.__byte_xor(temp, ciphertext[i - self.__block_size:i])
                i += 16

            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')


# key = get_random_bytes(16)
# iv = get_random_bytes(AES.block_size)
# nonce = get_random_bytes(int(AES.block_size/2))
# counter = 0
# ciphertext = AES_encrypt(key, "Zażółć", AES.MODE_CTR, nonce=nonce, counter=10)
# print(AES_decrypt(key, ciphertext, AES.MODE_CTR, nonce=nonce, counter=10))

temp = CustomModes(get_random_bytes(16))
temp.iv = get_random_bytes(16)
msg = "The examples above are classes and objects in their simplest form, and are not really useful in real life applications."
ciphertext = temp.encrypt_EBC(msg)
print(temp.decrypt_EBC(ciphertext))
ciphertext = temp.encrypt_CBC(msg)
print(temp.decrypt_CBC(ciphertext))
