from Crypto.Random import get_random_bytes
import random
import string
import timeit
import pandas
import gc
from ciphers import *

def randomString(length):
    alphanumericpunct = string.ascii_letters + string.digits
    return ''.join(random.choice(alphanumericpunct) for i in range(length))

def genStringLengths(start, amount):
    lengths = [start]
    for i in range(amount):
        lengths.append(lengths[i]*2)
    return lengths



#common beginning for measuring time for different crypto functions
# TODO: change 15 for to larger for ciphers other than RSA
string_length = genStringLengths(32, 15)
list_of_strings = []
for i in string_length:
    # start = timeit.default_timer()
    list_of_strings.append(randomString(i))
    # print("%d - %e s" % (i, timeit.default_timer() - start))
pass


# DES3-ECB - 16 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_ECB
name = "DES3-ECB-16"
key = get_random_bytes(16)
for string_it in list_of_strings:
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)


# AES-ECB - 16 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_ECB
name = "AES-ECB-16"
key = get_random_bytes(16)
for string_it in list_of_strings:
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)

# RSA
# Max length of plaintext for RSA less than k-11 bytes
# k - length of modulus in octets
# max length < 256 - 11 = 245 bytes != 244 characters !!!
encryption_times = []
decryption_times = []
name = "RSA"
public_key, private_key = get_key_pair()
for string_it in list_of_strings:
    if len(string_it) > 2**20:
        break
    gc.disable()
    if len(string_it) > 128:
        # split into 128-char parts
        split = [(string_it[i:i+128]) for i in range(0, len(string_it), 128)]
        # encode all parts
        ciphertext = []
        start = timeit.default_timer()
        for part in split:
            ciphertext.append(encrypt_RSA(part, public_key))
        duration = timeit.default_timer() - start
        encryption_times.append(duration)
        # decode all ciphertext parts
        plaintext = []
        start = timeit.default_timer()
        for part in ciphertext:
            plaintext.append(decrypt_RSA(part, private_key))
        duration = timeit.default_timer() - start
        decryption_times.append(duration)
    else:
        start = timeit.default_timer()
        encoded_data = encrypt_RSA(string_it, public_key)
        duration = timeit.default_timer() - start
        encryption_times.append(duration)
        start = timeit.default_timer()
        received_data = decrypt_RSA(encoded_data, private_key)
        duration = timeit.default_timer() - start
        decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times
})
df.to_csv('csv/%s_data.csv' % name)

# Salsa20
encryption_times = []
decryption_times = []
name = "Salsa20"
key = get_random_bytes(16)
for string_it in list_of_strings:
    gc.disable()
    start = timeit.default_timer()
    encoded_data = encrypt_Salsa20(string_it, key)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = decrypt_Salsa20(encoded_data, key)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)
