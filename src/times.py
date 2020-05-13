from Crypto.Random import get_random_bytes
from CustomModes import CustomModes
import random
import string
import timeit
import pandas
import gc, os
from ciphers import *

def randomString(length):
    alphanumeric = string.ascii_letters + string.digits
    return ''.join(random.choice(alphanumeric) for i in range(length))

def genStringLengths(start, amount):
    lengths = [start]
    for i in range(amount):
        lengths.append(lengths[i]*2)
    return lengths

try:
    os.mkdir("csv")
except:
    pass

#common beginning for measuring time for different crypto functions
string_length = genStringLengths(32, 25)
list_of_strings = []
for index, i in enumerate(string_length):
    # start = timeit.default_timer()
    if i <= 1024:
        list_of_strings.append(randomString(i))
    else:
        list_of_strings.append("".join((list_of_strings[index-1], list_of_strings[index-1])))
    # print("%d - %e s" % (len(list_of_strings[index]), timeit.default_timer() - start))
"""
# ---------------------------------------------------------------------------------------------------
# AES - Cryptodome
# ---------------------------------------------------------------------------------------------------

# 16 bytes key
# -------------------------------------
print("AES - 16")

# AES-ECB - 16 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_ECB
name = "AES-ECB-16"
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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

# AES-CBC - 16 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CBC
name = "AES-CBC-16"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-CFB - 16 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CFB
name = "AES-CFB-16"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-OFB - 16 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_OFB
name = "AES-OFB-16"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-CTR - 16 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CTR
name = "AES-CTR-16"
nonce = get_random_bytes(AES.block_size // 2)
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, nonce=nonce)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, nonce=nonce)
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

# 24 bytes key
# -------------------------------------
print("AES - 24")

# AES-ECB - 24 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_ECB
name = "AES-ECB-24"
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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

# AES-CBC - 24 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CBC
name = "AES-CBC-24"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-CFB - 24 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CFB
name = "AES-CFB-24"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-OFB - 24 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_OFB
name = "AES-OFB-24"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-CTR - 24 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CTR
name = "AES-CTR-24"
nonce = get_random_bytes(AES.block_size // 2)
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, nonce=nonce)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, nonce=nonce)
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

# 32 bytes key
# -------------------------------------
print("AES - 32")

# AES-ECB - 32 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_ECB
name = "AES-ECB-32"
key = get_random_bytes(32)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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

# AES-CBC - 32 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CBC
name = "AES-CBC-32"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(32)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-CFB - 32 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CFB
name = "AES-CFB-32"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(32)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-OFB - 32 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_OFB
name = "AES-OFB-32"
iv = get_random_bytes(AES.block_size)
key = get_random_bytes(32)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, iv=iv)
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

# AES-CTR - 32 bytes key
encryption_times = []
decryption_times = []
mode = AES.MODE_CTR
name = "AES-CTR-32"
nonce = get_random_bytes(AES.block_size // 2)
key = get_random_bytes(32)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = AES_encrypt(key, string_it, mode, nonce=nonce)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = AES_decrypt(key, encoded_data, mode, nonce=nonce)
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


# ---------------------------------------------------------------------------------------------------
# AES - Custom modes - 32 bytes key
# ---------------------------------------------------------------------------------------------------
print("Custom AES - 32")

key = get_random_bytes(32)
aes = CustomModes(key, "AES")
aes.iv = get_random_bytes(AES.block_size)
# as stated on https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
# "If the IV/nonce is random, then they can be combined together with the counter using any invertible 
# operation (concatenation, addition, or XOR) to produce the actual unique counter block for encryption."
# for our implementation we're using XOR of nonce and counter
aes.nonce = get_random_bytes(AES.block_size) 

# Custom-AES-ECB - 32 bytes key
encryption_times = []
decryption_times = []
name = "Custom-AES-ECB-32"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = aes.encrypt_EBC(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = aes.decrypt_EBC(encoded_data)
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

# Custom-AES-CBC - 32 bytes key
encryption_times = []
decryption_times = []
slow_decryption_times = []
name = "Custom-AES-CBC-32"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        slow_decryption_times.append('-')
        continue
    gc.disable()
    # encrypt
    start = timeit.default_timer()
    encoded_data = aes.encrypt_CBC(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    # slow decrypt
    start = timeit.default_timer()
    received_data = aes.decrypt_CBC_slow(encoded_data)
    duration = timeit.default_timer() - start
    slow_decryption_times.append(duration)
    # concurrent decrypt
    start = timeit.default_timer()
    received_data = aes.decrypt_CBC(encoded_data)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times,
    'slow_decryption_times':slow_decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)

# Custom-AES-CFB - 32 bytes key
encryption_times = []
decryption_times = []
slow_decryption_times = []
name = "Custom-AES-CFB-32"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        slow_decryption_times.append('-')
        continue
    gc.disable()
    # encrypt
    start = timeit.default_timer()
    encoded_data = aes.encrypt_CFB(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    # slow decrypt
    start = timeit.default_timer()
    received_data = aes.decrypt_CFB_slow(encoded_data)
    duration = timeit.default_timer() - start
    slow_decryption_times.append(duration)
    # concurrent decrypt
    start = timeit.default_timer()
    received_data = aes.decrypt_CFB(encoded_data)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times,
    'slow_decryption_times':slow_decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)

# Custom-AES-OFB - 32 bytes key
encryption_times = []
decryption_times = []
name = "Custom-AES-OFB-32"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    # encrypt
    start = timeit.default_timer()
    encoded_data = aes.encrypt_OFB(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    # decrypt
    start = timeit.default_timer()
    received_data = aes.decrypt_OFB(encoded_data)
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

# Custom-AES-CTR - 32 bytes key
encryption_times = []
decryption_times = []
slow_decryption_times = []
slow_encryption_times = []
name = "Custom-AES-CTR-32"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        slow_decryption_times.append('-')
        slow_encryption_times.append('-')
        continue
    gc.disable()
    # slow encrypt
    start = timeit.default_timer()
    encoded_data = aes.encrypt_CTR_slow(string_it)
    duration = timeit.default_timer() - start
    slow_encryption_times.append(duration)
    # slow decrypt
    start = timeit.default_timer()
    received_data = aes.decrypt_CTR_slow(encoded_data)
    duration = timeit.default_timer() - start
    slow_decryption_times.append(duration)
    # concurent encrypt
    start = timeit.default_timer()
    encoded_data = aes.encrypt_CTR(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    # concurrent decrypt
    start = timeit.default_timer()
    received_data = aes.decrypt_CTR(encoded_data)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'slow_encryption_times': slow_encryption_times,
    'decryption_times':decryption_times,
    'slow_decryption_times':slow_decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)


# ---------------------------------------------------------------------------------------------------
# DES3 - Cryptodome
# ---------------------------------------------------------------------------------------------------

# 16 bytes key
# -------------------------------------
print("DES3 - 16")

# DES3-ECB - 16 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_ECB
name = "DES3-ECB-16"
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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

# DES3-CBC - 16 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_CBC
name = "DES3-CBC-16"
iv = get_random_bytes(DES3.block_size)
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = DES3_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = DES3_decrypt(key, encoded_data, mode, iv=iv)
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

# DES3-CFB - 16 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_CFB
name = "DES3-CFB-16"
iv = get_random_bytes(DES3.block_size)
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = DES3_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = DES3_decrypt(key, encoded_data, mode, iv=iv)
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

# DES3-OFB - 16 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_OFB
name = "DES3-OFB-16"
iv = get_random_bytes(DES3.block_size)
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = DES3_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = DES3_decrypt(key, encoded_data, mode, iv=iv)
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

# DES3-CTR - 16 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_CTR
name = "DES3-CTR-16"
nonce = get_random_bytes(DES3.block_size // 2)
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = DES3_encrypt(key, string_it, mode, nonce=nonce)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = DES3_decrypt(key, encoded_data, mode, nonce=nonce)
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

# 24 bytes key
# -------------------------------------
print("DES3 - 24")

# DES3-ECB - 24 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_ECB
name = "DES3-ECB-24"
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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

# DES3-CBC - 24 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_CBC
name = "DES3-CBC-24"
iv = get_random_bytes(DES3.block_size)
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = DES3_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = DES3_decrypt(key, encoded_data, mode, iv=iv)
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

# DES3-CFB - 24 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_CFB
name = "DES3-CFB-24"
iv = get_random_bytes(DES3.block_size)
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = DES3_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = DES3_decrypt(key, encoded_data, mode, iv=iv)
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

# DES3-OFB - 24 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_OFB
name = "DES3-OFB-24"
iv = get_random_bytes(DES3.block_size)
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = DES3_encrypt(key, string_it, mode, iv=iv)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = DES3_decrypt(key, encoded_data, mode, iv=iv)
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

# DES3-CTR - 24 bytes key
encryption_times = []
decryption_times = []
mode = DES3.MODE_CTR
name = "DES3-CTR-24"
nonce = get_random_bytes(DES3.block_size // 2)
key = get_random_bytes(24)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = DES3_encrypt(key, string_it, mode, nonce=nonce)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = DES3_decrypt(key, encoded_data, mode, nonce=nonce)
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

# ---------------------------------------------------------------------------------------------------
# DES3 - Custom modes - 24 bytes key
# ---------------------------------------------------------------------------------------------------
print("Custom DES3 - 24")

key = get_random_bytes(24)
des3 = CustomModes(key, "DES3")
des3.iv = get_random_bytes(DES3.block_size)
# as stated on https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
# "If the IV/nonce is random, then they can be combined together with the counter using any invertible 
# operation (concatenation, addition, or XOR) to produce the actual unique counter block for encryption."
# for our implementation we're using XOR of nonce and counter
des3.nonce = get_random_bytes(DES3.block_size) 

# Custom-DES3-ECB - 24 bytes key
encryption_times = []
decryption_times = []
name = "Custom-DES3-ECB-24"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    start = timeit.default_timer()
    encoded_data = des3.encrypt_EBC(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    start = timeit.default_timer()
    received_data = des3.decrypt_EBC(encoded_data)
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

# Custom-DES3-CBC - 24 bytes key
encryption_times = []
decryption_times = []
slow_decryption_times = []
name = "Custom-DES3-CBC-24"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        slow_decryption_times.append('-')
        continue
    gc.disable()
    # encrypt
    start = timeit.default_timer()
    encoded_data = des3.encrypt_CBC(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    # slow decrypt
    start = timeit.default_timer()
    received_data = des3.decrypt_CBC_slow(encoded_data)
    duration = timeit.default_timer() - start
    slow_decryption_times.append(duration)
    # concurrent decrypt
    start = timeit.default_timer()
    received_data = des3.decrypt_CBC(encoded_data)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times,
    'slow_decryption_times':slow_decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)

# Custom-DES3-CFB - 24 bytes key
encryption_times = []
decryption_times = []
slow_decryption_times = []
name = "Custom-DES3-CFB-24"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        slow_decryption_times.append('-')
        continue
    gc.disable()
    # encrypt
    start = timeit.default_timer()
    encoded_data = des3.encrypt_CFB(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    # slow decrypt
    start = timeit.default_timer()
    received_data = des3.decrypt_CFB_slow(encoded_data)
    duration = timeit.default_timer() - start
    slow_decryption_times.append(duration)
    # concurrent decrypt
    start = timeit.default_timer()
    received_data = des3.decrypt_CFB(encoded_data)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times,
    'slow_decryption_times':slow_decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)

# Custom-DES3-OFB - 24 bytes key
encryption_times = []
decryption_times = []
name = "Custom-DES3-OFB-24"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    # encrypt
    start = timeit.default_timer()
    encoded_data = des3.encrypt_OFB(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    # decrypt
    start = timeit.default_timer()
    received_data = des3.decrypt_OFB(encoded_data)
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

# Custom-DES3-CTR - 24 bytes key
encryption_times = []
decryption_times = []
slow_decryption_times = []
slow_encryption_times = []
name = "Custom-DES3-CTR-24"
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        slow_decryption_times.append('-')
        slow_encryption_times.append('-')
        continue
    gc.disable()
    # slow encrypt
    start = timeit.default_timer()
    encoded_data = des3.encrypt_CTR_slow(string_it)
    duration = timeit.default_timer() - start
    slow_encryption_times.append(duration)
    # slow decrypt
    start = timeit.default_timer()
    received_data = des3.decrypt_CTR_slow(encoded_data)
    duration = timeit.default_timer() - start
    slow_decryption_times.append(duration)
    # concurent encrypt
    start = timeit.default_timer()
    encoded_data = des3.encrypt_CTR(string_it)
    duration = timeit.default_timer() - start
    encryption_times.append(duration)
    # concurrent decrypt
    start = timeit.default_timer()
    received_data = des3.decrypt_CTR(encoded_data)
    duration = timeit.default_timer() - start
    decryption_times.append(duration)
    gc.enable()
    gc.collect()
# save data
df = pandas.DataFrame(data={
    'string_length':string_length,
    'encryption_times':encryption_times,
    'slow_encryption_times':slow_encryption_times,
    'decryption_times':decryption_times,
    'slow_decryption_times':slow_decryption_times,
})
df.to_csv('csv/%s_data.csv' % name)
"""
# ---------------------------------------------------------------------------------------------------
# RSA - Cryptodome
# ---------------------------------------------------------------------------------------------------
print("RSA")

# Max length of plaintext for RSA less than k-11 bytes
# k - length of modulus in octets
# max length < 256 - 11 = 245 bytes != 244 characters !!!

# RSA - 1024 bits key
encryption_times = []
decryption_times = []
name = "RSA-1024"
public_key, private_key = get_key_pair(1024)
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
    gc.disable()
    if len(string_it) > 64:
        # split into 128-char parts
        split = [(string_it[i:i+64]) for i in range(0, len(string_it), 64)]
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

# RSA - 2048 bits key
encryption_times = []
decryption_times = []
name = "RSA-2048"
public_key, private_key = get_key_pair(2048)
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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

# RSA - 4096 bits key
encryption_times = []
decryption_times = []
name = "RSA-4096"
public_key, private_key = get_key_pair(4096)
for string_it in list_of_strings:
    if len(string_it) > 2**20 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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

# ---------------------------------------------------------------------------------------------------
# Salsa20 - Cryptodome
# ---------------------------------------------------------------------------------------------------
print("Salsa20")

# Salsa20 - 16 bytes key
encryption_times = []
decryption_times = []
name = "Salsa20-16"
key = get_random_bytes(16)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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

# Salsa20 - 32 bytes key
encryption_times = []
decryption_times = []
name = "Salsa20-32"
key = get_random_bytes(32)
for string_it in list_of_strings:
    if len(string_it) > 2**5 and duration > 20:
        encryption_times.append('-')
        decryption_times.append('-')
        continue
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