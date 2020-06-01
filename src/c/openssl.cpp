#include <iostream>
#include <cstring>
#include <cstdio>
#include <chrono>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <openssl/evp.h>
#include <openssl/err.h>



using namespace std;

void gen_random(unsigned char *s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main() {
    //clock_t start, end_enc, end_dec;
    FILE* fptr;

    int amount = 26;
    int lengths[26] = {32};
    // lengths to test
    for(int i = 1; i < amount; i ++){
        lengths[i] = lengths[i-1]*2;
        printf("%d, ", lengths[i]);
    }
    printf("Lengths done\n");
    unsigned char *input, *output, *result;
    /*
     * Name for file. 
     */ 
    char const *name = "./../../csv/OpenSSL-AES-CBC-32-noAESNI.csv";

    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(key, sizeof(key)*8, &enc_key);
    AES_set_decrypt_key(key, sizeof(key)*8, &dec_key);
    //printf("Key init done\n");

    fptr = fopen(name, "w");
    if(!fptr)
        return 1;
    fprintf(fptr,",string_length,encyption_times,decryption_times\n");
    //printf("File opened\n");

    // encryption/decryption loop
    for (size_t i = 0; i < amount; i++)
    {
        input = (unsigned char*)malloc(lengths[i]);
        output = (unsigned char*)malloc(lengths[i] + 16);
        result = (unsigned char*)malloc(lengths[i] + 16);
        gen_random(input, lengths[i]);
        //printf("Generated random string\n");
        // encrypt
        memset(iv, 0, AES_BLOCK_SIZE);
        //printf("IV memset\n");
        auto start = chrono::high_resolution_clock::now();
        int len = encrypt(input, lengths[i], key, iv, output);
        auto end_enc = chrono::high_resolution_clock::now() - start;
        //printf("Encryption done\n");
        free(input);
        // decrypt
        memset(iv, 0, AES_BLOCK_SIZE);
        start = chrono::high_resolution_clock::now();
        decrypt(output, len, key, iv, result);
        auto end_dec = chrono::high_resolution_clock::now() - start;
        //printf("Decryption done\n");
        free(output);
        free(result);
        // save to file
        fprintf(fptr, "%d,%d,%f,%f\n", (int) i, lengths[i], chrono::duration<double, milli>(end_enc).count() / 1000, chrono::duration<double, milli>(end_dec).count() / 1000);
        printf("Wrote to file %d time(s).\n", (int) i+1);
    }
    
    fclose(fptr);
    /*int size = 1073741824;
    //int size = 1024*1024;
    unsigned char *input = (unsigned char *)malloc(size);

    gen_random(input, size);

    unsigned char *output = (unsigned char *)malloc(size);
    unsigned char *result = (unsigned char *)malloc(size);



    memset(iv, 0, AES_BLOCK_SIZE);
    start = clock();
    int len = encrypt(input, size, key, iv, output);
    cout << "CBC enc: \t" << (clock() - start ) / (double) CLOCKS_PER_SEC << endl;

	memset(iv, 0, AES_BLOCK_SIZE);
    start = clock();
    decrypt(output, len, key, iv, result);
    cout << "CBC dec: \t" << (clock() - start ) / (double) CLOCKS_PER_SEC << endl;*/
}