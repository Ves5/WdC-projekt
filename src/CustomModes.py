from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor
from typing import List

from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class CustomModes:
    """
    Class to make block encryption using different modes and with transparent parallelism.
    Default is AES.
    Other algorithm is DES3
    """
    
    __result: List

    def __init__(self, key: bytes, algorithm="AES"):
        """
        Initialize the class for AES/DES3 encryption/decryption
        :param key: key for AES/DES3 ECB block
        :param algorithm: algorithm to use: AES/DES3; default is AES
        """

        self.__executor = ThreadPoolExecutor(max_workers=3)
        self.__result = []  # place for results of workers
        self.__algorithm = algorithm

        # initialize chosen algorithm
        if algorithm == "AES":
            self.__cipher = AES.new(key, AES.MODE_ECB)  # used just as an encryption block
            self.__block_size = AES.block_size
        # place for initialization for other algorithms - remember about updating init DocString
        elif algorithm == "DES3":
            self.__cipher = DES3.new(key, DES3.MODE_ECB)
            self.__block_size = DES3.block_size
        
        self.iv = None  # initialization vector needed for some modes
        self.counter = 0 # counter needed for CTR mode
        self.nonce = None # nonce needed for CTR mdoe

    @staticmethod
    def __byte_xor(ba1, ba2):
        """
        Perform xor on two byte arrays
        """
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    def __EBC_encrypt_worker(self, plaintext: bytes, index: int):
        """
        Encrypt plaintext of one block and put in result list at index
        :param plaintext: block to be encrypted
        :param index: index for result
        """
        self.__result[index:index + self.__block_size] = self.__cipher.encrypt(plaintext)

    def __EBC_decrypt_worker(self, ciphertext: bytes, index: int):
        """
        Decrypt ciphertext of one block and put in result list at index
        :param ciphertext: block to be decrypted
        :param index: index for result
        """
        self.__result[index:index + self.__block_size] = self.__cipher.decrypt(ciphertext)

    def encrypt_EBC(self, plaintext: str):
        """
        Perform EBC encryption using AES/DES3 with transparent concurrency
        :param plaintext: text to be encrypted
        :return: ciphertext
        """
        plaintext = pad(bytes(plaintext, 'utf-8'), self.__block_size)
        status = []
        i = 0
        self.__result = [None] * len(plaintext)

        # place jobs for executor for single blocks
        while i < len(plaintext):
            status.append(self.__executor.submit(self.__EBC_encrypt_worker, plaintext[i:i + self.__block_size], i))
            i += self.__block_size

        # wait for all jobs to be completed
        futures.wait(status)
        return bytes(self.__result)

    def decrypt_EBC(self, ciphertext: bytes):
        """
        Perform EBC decryption using AES/DES3 with transparent concurrency
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        status = []
        i = 0
        self.__result = [None] * len(ciphertext)

        # place jobs for executor for single blocks
        while i < len(ciphertext):
            status.append(self.__executor.submit(self.__EBC_decrypt_worker, ciphertext[i:i + self.__block_size], i))
            i += self.__block_size

        # wait for all jobs to be completed
        futures.wait(status)
        plaintext = unpad(bytes(self.__result), self.__block_size)
        return plaintext.decode('utf-8')

    def encrypt_CBC(self, plaintext: str):
        """
        Perform CBC encryption using AES/DES3; initialization vector must be set
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
            i = self.__block_size
            while i < len(plaintext):
                temp = self.__byte_xor(plaintext[i:i + self.__block_size], self.__result[i - self.__block_size:i])
                self.__result[i:i + self.__block_size] = self.__cipher.encrypt(temp)
                i += self.__block_size

            return bytes(self.__result)

    def __CBC_decrypt_worker(self, ciphertext: bytes, previous: bytes, index: int):
        """
        Decrypt ciphertext of block size length and put in result list at index
        :param ciphertext: block to be decrypted
        :param index: index for result
        """
        self.__result[index:index + self.__block_size] = self.__byte_xor(self.__cipher.decrypt(ciphertext), previous)

    def decrypt_CBC(self, ciphertext: bytes):
        """
        Perform CBC decryption using AES/DES3 with transparent concurrency; initialization vector must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """

        if self.iv is not None:
            self.__result = [None] * len(ciphertext)

            # first block into jobs
            status = [self.__executor.submit(self.__CBC_decrypt_worker, ciphertext[0:self.__block_size], self.iv, 0)]

            # place all next blocks in jobs queue
            i = self.__block_size
            while i < len(ciphertext):
                status.append(self.__executor.submit(self.__CBC_decrypt_worker, ciphertext[i:i + self.__block_size],
                                                     ciphertext[i - self.__block_size:i], i))
                i += self.__block_size

            # wait for all jobs to be completed
            futures.wait(status)
            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')

    def decrypt_CBC_slow(self, ciphertext: bytes):
        """
        Perform CBC decryption using AES/DES3 without concurrency; initialization vector must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        if self.iv is not None:
            self.__result = [None] * len(ciphertext)

            # first block
            temp = self.__cipher.decrypt(ciphertext[0:self.__block_size])
            self.__result[0:self.__block_size] = self.__byte_xor(temp, self.iv)

            # all next blocks
            i = self.__block_size
            while i < len(ciphertext):
                temp = self.__cipher.decrypt(ciphertext[i:i + self.__block_size])
                self.__result[i:i + self.__block_size] = self.__byte_xor(temp, ciphertext[i - self.__block_size:i])
                i += self.__block_size

            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')

    def encrypt_CFB(self, plaintext: str):
        """
        Perform CFB encryption using AES/DES3; initialization vector must be set
        :param plaintext: text to be encrypted
        :return: ciphertext
        """
        if self.iv is not None:
            plaintext = pad(bytes(plaintext, 'utf-8'), self.__block_size)
            self.__result = [None] * len(plaintext)
            
            # first block
            temp = self.__cipher.encrypt(self.iv)
            self.__result[0:self.__block_size] = self.__byte_xor(temp, plaintext[0:self.__block_size])

            i=self.__block_size
            while i < len(plaintext):
                temp = self.__cipher.encrypt(bytes(self.__result[(i - self.__block_size):i]))
                self.__result[i:i+self.__block_size] = self.__byte_xor(temp, plaintext[i:i + self.__block_size])
                i += self.__block_size
        
        return bytes(self.__result)

    def __CFB_decrypt_worker(self, ciphertext:bytes , previous: int, index: int):
        """
        Decrypt ciphertext of block size length and put in result list at index
        :param ciphertext: block to be decrypted
        :param index: index for result
        """
        self.__result[index: index + self.__block_size] = self.__byte_xor(self.__cipher.encrypt(previous), ciphertext)

    def decrypt_CFB(self, ciphertext: bytes):
        """
        Perform CFB decryption using AES/DES3 with transparent concurrency; initialization vector must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        if self.iv is not None:
            self.__result = [None] * len(ciphertext)

            # first block into jobs
            status = [self.__executor.submit(self.__CFB_decrypt_worker, ciphertext[0:self.__block_size],
                      self.iv, 0)]
            
            # place all next blocks in jobs queue
            i = self.__block_size
            while i < len(ciphertext):
                status.append(self.__executor.submit(self.__CFB_decrypt_worker, ciphertext[i:i+self.__block_size],
                              ciphertext[i-self.__block_size:i], i))
                i += self.__block_size

            # wait for all jobs to finish
            futures.wait(status)
            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')

    def decrypt_CFB_slow(self, ciphertext: bytes):
        """
        Perform CFB decryption using AES/DES3 without concurrency; initialization vector must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        if self.iv is not None:
            self.__result = [None] * len(ciphertext)

            # first block
            temp = self.__cipher.encrypt(self.iv)
            self.__result[0:self.__block_size] = self.__byte_xor(temp, ciphertext[0: self.__block_size])

            # all next blocks
            i = self.__block_size
            while i < len(ciphertext):
                temp = self.__cipher.encrypt(ciphertext[i - self.__block_size:i])
                self.__result[i:i+self.__block_size] = self.__byte_xor(temp, ciphertext[i:i+self.__block_size])
                i += self.__block_size
            
            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')

    def encrypt_OFB(self, plaintext: str):
        """
        Perform OFB encryption using AES/DES3; initialization vector must be set
        :param plaintext: text to be encrypted
        :return: ciphertext
        """
        if self.iv is not None:
            plaintext = pad(bytes(plaintext, 'utf-8'), self.__block_size)
            self.__result = [None] * len(plaintext)

            # first block
            temp = self.__cipher.encrypt(self.iv)
            self.__result[0:self.__block_size] = self.__byte_xor(temp, plaintext[0:self.__block_size])

            # all other blocks
            i = self.__block_size
            while i < len(plaintext):
                temp = self.__cipher.encrypt(temp)
                self.__result[i:i+self.__block_size] = self.__byte_xor(temp, plaintext[i:i+self.__block_size])
                i += self.__block_size

            return bytes(self.__result)

    def decrypt_OFB(self, ciphertext: bytes):
        """
        Perform OFB decryption using AES/DES3; initialization vector must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        if self.iv is not None:
            self.__result = [None] * len(ciphertext)

            # first block
            temp = self.__cipher.encrypt(self.iv)
            self.__result[0:self.__block_size] = self.__byte_xor(temp, ciphertext[0:self.__block_size])

            # all other blocks
            i = self.__block_size
            while i < len(ciphertext):
                temp = self.__cipher.encrypt(temp)
                self.__result[i:i+self.__block_size] = self.__byte_xor(temp, ciphertext[i:i+self.__block_size])
                i += self.__block_size
            
            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')

    def __CRT_encrypt_worker(self, plaintext: bytes, ctrblock: bytes, index: int):
        """
        Encrypt ciphertext of block size length and put in result list at index
        :param plaintext: block to be encrypted
        :param index: index for result
        """
        self.__result[index:index + self.__block_size] = self.__byte_xor(plaintext, self.__cipher.encrypt(ctrblock))

    def encrypt_CTR(self, plaintext: str):
        """
        Perform CTR encryption using AES/DES3 with transparent concurrency; nonce must be set
        :param plaintext: plaintext to be encrypted
        :return: ciphertext
        """
        if self.nonce is not None:
            temp_counter = self.counter
            plaintext = pad(bytes(plaintext, 'utf-8'), self.__block_size)
            self.__result = [None] * len(plaintext)

            # convert all blocks to jobs
            status = []
            i = 0
            while i < len(plaintext):
                ctrblock = self.__byte_xor(self.nonce, self.counter.to_bytes(8, 'big'))
                status.append(self.__executor.submit(self.__CRT_encrypt_worker, plaintext[i:i+self.__block_size],
                                                     ctrblock, i))
                i += self.__block_size
                self.counter += 1
            
            self.counter = temp_counter
            futures.wait(status)
            return bytes(self.__result)
    
    def encrypt_CTR_slow(self, plaintext: str):
        """
        Perform CTR encryption using AES/DES3 without concurrency; nonce must be set
        :param plaintext: plaintext to be encrypted
        :return: ciphertext
        """
        if self.nonce is not None:
            temp_counter = self.counter
            plaintext = pad(bytes(plaintext, 'utf-8'), self.__block_size)
            self.__result = [None] * len(plaintext)

            # convert all blocks to jobs
            i = 0
            while i < len(plaintext):
                ctrblock = self.__byte_xor(self.nonce, self.counter.to_bytes(8, 'big'))
                temp = self.__cipher.encrypt(ctrblock)
                self.__result[i:i+self.__block_size] = self.__byte_xor(temp, plaintext[i:i+self.__block_size])
                i += self.__block_size
                self.counter += 1
            
            self.counter = temp_counter

            return bytes(self.__result)

    def __CRT_decrypt_worker(self, ciphertext: bytes, ctrblock: bytes, index: int):
        """
        Decrypt ciphertext of block size length and put in result list at index
        :param ciphertext: block to be decrypted
        :param index: index for result
        """
        self.__result[index:index + self.__block_size] = self.__byte_xor(ciphertext, self.__cipher.encrypt(ctrblock))

    def decrypt_CTR(self, ciphertext: bytes):
        """
        Perform CTR decryption using AES/DES3 with transparent concurrency; nonce must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        if self.nonce is not None:
            self.__result = [None] * len(ciphertext)

            # convert all blocks to jobs
            status = []
            i = 0
            while i < len(ciphertext):
                ctrblock = self.__byte_xor(self.nonce, self.counter.to_bytes(8, 'big'))
                status.append(self.__executor.submit(self.__CRT_decrypt_worker, ciphertext[i:i+self.__block_size],
                                                     ctrblock, i))
                i += self.__block_size
                self.counter += 1

            # wait for all jobs to finish
            futures.wait(status)
            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')

    def decrypt_CTR_slow(self, ciphertext: bytes):
        """
        Perform CTR decryption using AES/DES3 without concurrency; nonce must be set
        :param ciphertext: ciphertext to be decrypted
        :return: plaintext
        """
        if self.nonce is not None:
            self.__result = [None] * len(ciphertext)

            # convert all blocks to jobs
            i = 0
            while i < len(ciphertext):
                ctrblock = self.__byte_xor(self.nonce, self.counter.to_bytes(8, 'big'))
                temp = self.__cipher.encrypt(ctrblock)
                self.__result[i:i+self.__block_size] = self.__byte_xor(temp, ciphertext[i:i+self.__block_size])
                i += self.__block_size
                self.counter += 1
            
            self.counter = 0

            plaintext = unpad(bytes(self.__result), self.__block_size)
            return plaintext.decode('utf-8')


text = "text to be encrypted, z polśkimi znąkami"
rkey = get_random_bytes(24)
riv = get_random_bytes(8)
rnonce = get_random_bytes(8)

des3 = CustomModes(rkey, "DES3")
des3.iv = riv
des3.nonce = rnonce

des3.counter = 126
print(text)
encrypted = des3.encrypt_CTR(text)
print(encrypted)
decrypted = des3.decrypt_CTR(encrypted)
print(decrypted)