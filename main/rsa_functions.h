#ifndef RSA_FUNCTIONS
#define RSA_FUNCTIONS

int miller_rabin_test(mbedtls_mpi* n, mbedtls_mpi* d);
void get_prns(unsigned char *randomBlock, size_t size);
mbedtls_pk_context* gen_key_pair();
int check_primality(mbedtls_mpi *n, int iters);
void test_keys(mbedtls_pk_context *pk);
void store_priv_key(const uint8_t* key_data, size_t key_len);
void save_rsa_private_key(mbedtls_pk_context *pk);
void test_private_key_encrypted_write(const esp_partition_t *partition, const unsigned char *original_key, size_t key_len);
void get_message_digest(unsigned char *message, size_t message_len, unsigned char *hash);
void test_hash(uint8_t *message_digest, size_t length);
void get_digital_sig(mbedtls_pk_context* pk, unsigned char * message_digest);
#define SHA512_DIGEST_LENGTH 64

#endif