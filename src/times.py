import random
import string
import time
import os
import pandas

#common beginning for measuring time for different crypto functions
string_length = [10, 20, 30]
list_of_strings = []
for i in string_length:
    list_of_strings.append(randomString(i))
pass


# RSA
encryption_times = []
decryption_times = []
public_key, private_key = get_key_pair()
for string_it in list_of_strings:
    start = time.time()
    encoded_data = encrypt_RSA(string_it, public_key)
    duration = time.time() - start
    encryption_times.append(duration)
    start = time.time()
    received_data = decrypt_RSA(encoded_data, private_key)
    duration = time.time() - start
    decryption_times.append(duration)

df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times
})
df.to_csv('RSA_data.csv')

# Salsa20
encryption_times = []
decryption_times = []
key = os.urandom(16)
for string_it in list_of_strings:
    start = time.time()
    encoded_data = encrypt_Salsa20(string_it, key)
    duration = time.time() - start
    encryption_times.append(duration)
    start = time.time()
    received_data = decrypt_Salsa20(encoded_data, key)
    duration = time.time() - start
    decryption_times.append(duration)
df = pandas.DataFrame({
    'string_length':string_length,
    'encryption_times':encryption_times,
    'decryption_times':decryption_times,
})
df.to_csv('Salsa20_data.csv')