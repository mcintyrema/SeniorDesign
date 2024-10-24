#ifndef RSA_FUNCTIONS
#define RSA_FUNCTIONS

/* C libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
/* wolfSSL */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/random.h"
/* mbedTLS */
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include <mbedtls/sha512.h>
#include <mbedtls/sha256.h>
/* ESP32-S3 */
#include "esp_partition.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include <esp_wifi.h>
// #include <esp_netif.h>
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_now.h"

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
void get_digital_sig(mbedtls_pk_context *pk, unsigned char *message_digest, mbedtls_mpi *digital_signature);
// void verify_dig_sig(mbedtls_pk_context *pk, mbedtls_mpi digital_signature, unsigned char *message_digest);
void verify_dig_sig(mbedtls_mpi *N, mbedtls_mpi *E, mbedtls_mpi *digital_signature, unsigned char *message_digest);

#define SHA512_DIGEST_LENGTH 64
extern int valid_signature;

#endif