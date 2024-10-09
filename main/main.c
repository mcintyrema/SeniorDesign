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
/* ESP32-S3 */
#include "esp_partition.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"

#define SHA512_DIGEST_LENGTH 64


//Prototypes
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

// CSPRNG returns number sequence
void get_prns(unsigned char *randomBlock, size_t size)
{
  // Create a random number generator instance
  WC_RNG rng;
  int ret;

  // Initialize RNG
  ret = wc_InitRng(&rng);
  if (ret != 0) {
      printf("Failed to initialize RNG\n");
      return;
  }

  ret = wc_RNG_GenerateBlock(&rng, randomBlock, size);
  if (ret != 0) {
      printf("Failed to generate block\n");
  } 
    wc_FreeRng(&rng);
}


mbedtls_pk_context* gen_key_pair(){
    int key_size = 2048;
    int exponent = 65537;

    // Initialize structs
    // mbedtls_pk_context rsa;
    mbedtls_pk_context* pk = (mbedtls_pk_context*)malloc(sizeof(mbedtls_pk_context));
    mbedtls_ctr_drbg_context ctr_drbg; // Counter mode deterministic random byte generator state
    mbedtls_entropy_context entropy; // Entropy context structure
    const char *pers = "rsa_keypair"; // Personalized string for entropy
  
    // Initialize contexts
    mbedtls_pk_init(pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed drbg with entropy
    if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,  (const unsigned char *)pers, strlen(pers)) != 0)
    {
      // Free memory if mbedtls_ctr_drbg_seed fails
      mbedtls_ctr_drbg_free(&ctr_drbg);
      return NULL;
    }
      
    // Check setup
    if(mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
    {
      printf("Setup failed\n");
      return NULL;
    }

    // Generate key pair
    if(mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk), mbedtls_ctr_drbg_random, &ctr_drbg, key_size, exponent) != 0) 
    {
      return NULL; //upon failure
    }
    else
    {
      return pk;
    }
    
}


// Check primality test
int check_primality(mbedtls_mpi *n, int iters){
  /* Handle base cases for n < 3 */
  // Test if n < 2 and return false if yes
  if (mbedtls_mpi_cmp_int(n, 2) < 0) { 
    printf("n is less than 2.\n");
    return -1;
  }

  //Test if n is even
  mbedtls_mpi remainder, quotient;
  mbedtls_mpi_init(&remainder);
  mbedtls_mpi_init(&quotient);
  mbedtls_mpi_div_int(&quotient, &remainder, n, 2);
 
  if(mbedtls_mpi_cmp_int(&remainder, 0) == 0) {
    return -1;
  } 

  mbedtls_mpi_free(&quotient);
  mbedtls_mpi_free(&remainder);

  // Find odd number d such that n-1 can be written as d*2^r, n = 2^d*r+1
  mbedtls_mpi d, temp;
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&temp);
  mbedtls_mpi_sub_int(&d, n, 1); // d = n - 1, subtraction of an MPI and int
  // Divide d by 2 until odd
  while (mbedtls_mpi_cmp_int(&d, 0) > 0 && mbedtls_mpi_cmp_int(&d, 2) >= 0) {
    mbedtls_mpi_div_int(&d, &quotient, &d, 2); // d = d / 2
    if (mbedtls_mpi_cmp_int(&d, 1) == 0) {
      break; // Stop when d reaches 1
    }
  }

  // Iterate
  for(int i = 0; i < iters; i++){
    if(miller_rabin_test(n, &d) == 1){
      return 1; //false      
    }    
  }

  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&temp);
  return 0;
}


// Miller-Rabin Primality Test (for iterating)
int miller_rabin_test(mbedtls_mpi* n, mbedtls_mpi* d){
  // Pick random number 'a' in range [2, n-2] 
  mbedtls_mpi a;
  mbedtls_mpi temp; // hold value of n-2
  mbedtls_mpi_init(&a);
  mbedtls_mpi_init(&temp);
  mbedtls_mpi_sub_int(&temp, n, 2);
  // Create RNG for parameter
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char *pers = "personal_seed";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
  // Assign a with random number
  mbedtls_mpi_random(&a, 2, &temp, mbedtls_ctr_drbg_random, &ctr_drbg);

  // Compute x = pow(a, d) % n
  mbedtls_mpi x;
  mbedtls_mpi_init(&x);
  mbedtls_mpi_exp_mod(&x, &a, d, n, NULL);

  // If x == 1 or x == n-1, return true
  mbedtls_mpi_sub_int(&temp, n, 1); // n-1
  if (mbedtls_mpi_cmp_int(&x, 1) == 0 || mbedtls_mpi_cmp_mpi(&temp, &x) == 0){
    return 0; 
  }
  // Iterate r-1 times
  while (mbedtls_mpi_cmp_mpi(d, &temp) != 0)
  {
    mbedtls_mpi_mul_mpi(&temp, &x, &x); // temp = x * x
    mbedtls_mpi_mod_mpi(&x, &temp, n); // x = temp % n
    mbedtls_mpi_mul_int(d, d, 2); // d *= 2

    if (mbedtls_mpi_cmp_int(&x, 1) == 0) return -1;
    mbedtls_mpi_sub_int(&temp, n, 1); // n-1
    if (mbedtls_mpi_cmp_mpi(&temp, &x)) return 0;
  }

  mbedtls_mpi_free(&a);
  mbedtls_mpi_free(&temp);
  mbedtls_mpi_free(&x);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return -1;
}


void test_keys(mbedtls_pk_context *pk){
  // Check if context contains public key
  if (mbedtls_rsa_check_pubkey(mbedtls_pk_rsa(*pk)) != 0) {
      printf("Public key generation failed.\n");
      return;
  }

  // Check if context contains an RSA private key and ensure keys are inverses
  if (mbedtls_rsa_check_privkey(mbedtls_pk_rsa(*pk)) != 0) {
      printf("Private key generation failed.\n");
      return;
  }  

  // Check modulus length
  if (mbedtls_rsa_get_len(mbedtls_pk_rsa(*pk)) <= 256) {
    printf("Modulus length is %d bytes.\n", mbedtls_rsa_get_len(mbedtls_pk_rsa(*pk)));
  }   

  // Extract core parameters of RSA key
  mbedtls_mpi P, Q, N, D, E;
  mbedtls_mpi_init(&P); 
  mbedtls_mpi_init(&Q);
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&D);
  mbedtls_mpi_init(&E);
  mbedtls_rsa_export(mbedtls_pk_rsa(*pk), &N, &P, &Q, &D, &E);

  // Test core parameters of RSA key
  // Primality test of P
    if (check_primality(&P, 10) == 0) {
      printf("P is prime.\n");
    } 
    else{
      printf("P is not prime.\n");
    }

    //Test primality of Q
    if (check_primality(&Q, 10) == 0){
      printf("Q is prime.\n");
    } 
    else{
      printf("Q is not prime.\n");
    }

    // Verify the relation N = P * Q
    mbedtls_mpi product;
    mbedtls_mpi_init(&product);
    mbedtls_mpi_mul_mpi(&product, &P, &Q);
    
    if(mbedtls_mpi_cmp_mpi(&N, &product) == 0) {
      printf("N is equal to P * Q.\n");
    } 
    else{
      printf("N is not equal to P * Q.\n");
    }

    // Clean up
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&product);
}


void save_rsa_private_key(mbedtls_pk_context *pk) {
    // Create buffer to hold key
    unsigned char *priv_key_buf = malloc(2080);  
    // unsigned char *priv_key_buf = malloc(260);  
    if (priv_key_buf == NULL) {
        printf("Memory allocation failed\n");
        return; 
    }

    // Write key to the buffer
    if (mbedtls_pk_write_key_pem(pk, priv_key_buf, 2080) != 0) {
        printf("Failed to write private key to buffer\n");
        free(priv_key_buf); // Free allocated memory
        return;
    }

    // Flash key to partition
    store_priv_key(priv_key_buf, strlen((char *)priv_key_buf));
    free(priv_key_buf); 
}
              

void store_priv_key(const uint8_t* key_data, size_t key_len) {
  // Pad key so length is nearest multiple of 16
  size_t padded_key_len = (key_len + 15) & ~15; 

  // Allocate a new buffer with the padded length
  unsigned char *padded_key_data = malloc(padded_key_len);
  if (!padded_key_data) {
      printf("Failed to allocate memory for padded key data.\n");
      return;
  }

  // Copy the key data to the padded buffer and fill the rest with zeros
  memcpy(padded_key_data, key_data, key_len);
  if (padded_key_len > key_len) {
      memset(padded_key_data + key_len, 0, padded_key_len - key_len);  // Padding with zeros
  }

  const esp_partition_t* partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "priv_key");
  if (partition == NULL) {
      printf("Failed to find partition\n");
      return;
  }

  // Verify key size is not greater than partition
  if (key_len > partition->size) {
      printf("Error: Key size (%zu bytes) exceeds partition size (%" PRIu32 " bytes)\n", key_len, partition->size);
      return;
  }

  // Clear partition before writing
  esp_err_t err = esp_partition_erase_range(partition, 0, partition->size);
  if (err != ESP_OK) {
      printf("Failed to erase partition. Error: %s\n", esp_err_to_name(err));
      return;
  }

  // Write to flash
  err = esp_partition_write(partition, 0, padded_key_data, padded_key_len);
  if (err != ESP_OK) {
      printf("Failed to write private key to partition. Error: %s\n", esp_err_to_name(err));
      free(padded_key_data);  // Clean up the allocated buffer
      return;
  }
  printf("Private key stored in flash successfully\n");
  free(padded_key_data);

  // Delay before testing if key was written
  vTaskDelay(100 / portTICK_PERIOD_MS); 
  test_private_key_encrypted_write(partition, key_data, key_len);
}


void test_private_key_encrypted_write(const esp_partition_t *partition, const unsigned char *original_key, size_t key_len) {
    // Ensure length of key is a multiple of 16
    size_t padded_key_len = (key_len + 15) & ~15;

    // Allocate buffer for reading back data from the partition
    unsigned char *read_back_data = malloc(padded_key_len);
    if (!read_back_data) {
        printf("Failed to allocate memory for reading back data.\n");
        return;
    }


    esp_err_t err = esp_partition_read_raw(partition, 0, read_back_data, key_len);
    if (err != ESP_OK) {
        printf("Failed to read back private key from partition. Error: %s\n", esp_err_to_name(err));
        return;
    }
    if (memcmp(original_key, read_back_data, key_len) == 0) {
        printf("Warning: The private key was written but does not appear to be encrypted!\n");
    } else {
        printf("The private key is encrypted on flash.\n");
    }

    free(read_back_data);
}


void get_message_digest(unsigned char *message, size_t message_len, unsigned char *hash){
    mbedtls_sha512_context sha_ctx; 
    mbedtls_sha512_init(&sha_ctx);
    
    // SHA-512 checksum calculation
    mbedtls_sha512_starts(&sha_ctx, 0); 
    // Update the context with the message for ongoing checksum calculation
    mbedtls_sha512_update(&sha_ctx, message, message_len);
    // Finish hashing and write result to ouput buffer
    mbedtls_sha512_finish(&sha_ctx, hash);

    mbedtls_sha512_free(&sha_ctx);
    return;
}


void test_hash(uint8_t *message_digest, size_t length) {
    if (message_digest == NULL || length == 0) {
      printf("Invalid message digest or length.\n");
      return; 
    }

    printf("Message Digest Length: %zu bytes\n", length);
    printf("SHA-512 Hash: \n");
    
    // Display bytes of the message digest in hex
    for (size_t i = 0; i < length; i++) {
        printf("%02x", message_digest[i]);
    }
    printf("\n");
    return;
}


void get_digital_sig(mbedtls_pk_context *pk, unsigned char *message_digest){
  // Extract core parameters of RSA key
  mbedtls_mpi P, Q, N, D, E;
  mbedtls_mpi_init(&P); 
  mbedtls_mpi_init(&Q);
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&D);
  mbedtls_mpi_init(&E);
  mbedtls_rsa_export(mbedtls_pk_rsa(*pk), &N, &P, &Q, &D, &E);
  // printf("RSA parameters exported.\n");

  // Verify m < n
  size_t modulus_size = mbedtls_mpi_size(&N);
  if(SHA512_DIGEST_LENGTH > modulus_size){
    printf("Message digest larger than modulus. Exiting...");
    printf("Digest size: %d\n Modulus size: %d\n", SHA512_DIGEST_LENGTH, modulus_size);
    return;
  }
  else{
    printf("Size of message digest is less than size of modulus.\n");
  }

  // Convert message_digest to mbedtls_mpi
  mbedtls_mpi message_mpi;
  mbedtls_mpi_init(&message_mpi);
  mbedtls_mpi_read_binary(&message_mpi, message_digest, SHA512_DIGEST_LENGTH);

  // Get signature: S = m^d mod n
  mbedtls_mpi digital_signature;
  mbedtls_mpi_init(&digital_signature); 
  mbedtls_mpi_exp_mod(&digital_signature, &message_mpi, &D, &N, NULL);

  // Verify 
  mbedtls_mpi message;
  mbedtls_mpi_init(&message); 
  int ret = mbedtls_mpi_exp_mod(&message, &digital_signature, &E, &N, NULL);
  if (ret != 0) {
    printf("Signature is invalid.\n");
  }
  else {
    size_t size = mbedtls_mpi_size(&message);
    unsigned char *buffer = malloc(size);

    // Write the MPI to buffer in binary format
    mbedtls_mpi_write_binary(&message, buffer, size);
    
    // Print the decrypted message in hexadecimal format, prints the hash
    printf("Decrypted message: \n");
    for (size_t i = 0; i < size; i++) {
      printf("%02x", buffer[i]);
    }

    ret = memcmp(buffer, message_digest, SHA512_DIGEST_LENGTH); //compare bytes
    if(ret == 0) {
      printf("\nHashes match!\n");
      printf("Signature is valid.\n");
    } 
    else{
      printf("\nHashes do not match.\n");
      printf("Signature is invalid.\n");
    }
  }
}


int main(){
  // Subscribe task to WDT
  esp_task_wdt_add(NULL);
  esp_task_wdt_reset();
  esp_task_wdt_delete(NULL);
  esp_task_wdt_deinit();

  // Generate CSPRNS
  printf("Generating random sequence...\n");
  unsigned char sequence[4];
  get_prns(sequence, sizeof(sequence));
  printf("Random sequence generated successfully.\n");
  printf("Generated sequence: 0x");
  for (int i = 0; i < sizeof(sequence); i++) {
      printf("%02x", sequence[i]);
  }
  
  // Generate RSA key pair and store in RSA context
  printf("\nGenerating key pair...\n");
  mbedtls_pk_context* pk = gen_key_pair();
  test_keys(pk);
  printf("Key pair generated successfully.\n");

  // Encrypts only the private key in its own partition while the rest of the data is plaintext
  printf("Storing private key...\n");
  save_rsa_private_key(pk);
  printf("Private key stored successfully.\n");

  // Generate message digest using SHA-512
  printf("Generating message digest...\n");
  size_t sequence_len = sizeof(sequence);
  unsigned char *message_digest = malloc(SHA512_DIGEST_LENGTH);
  get_message_digest(sequence, sequence_len, message_digest);
  test_hash(message_digest, SHA512_DIGEST_LENGTH);
  printf("Message digest generated successfully.\n");

  // Generate digital signature
  printf("Generating digital signature...\n");
  get_digital_sig(pk, message_digest);
  printf("Digital signature generated successfully.\n");

  mbedtls_pk_free(pk);
  free(message_digest);
  return 0;
}


void app_main(void)
{
  main();
}