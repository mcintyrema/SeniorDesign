/* C libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* wolfSSL */
// #include "wolfssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/random.h"
/* mbedTLS */
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
/* ESP32-S3 */
// #include "SPIFFS.h" //use on Arduino
#include "esp_partition.h"
#include <inttypes.h> 
#include "esp_err.h"
#include "soc/lldesc.h"
// #include "soc/sha_struct.h"


//Prototypes
int miller_rabin_test(mbedtls_mpi* n, mbedtls_mpi* d);
void get_prns(unsigned char *randomBlock, size_t size);
mbedtls_pk_context* gen_key_pair();
int check_primality(mbedtls_mpi *n, int iters);
void test_keys(mbedtls_pk_context *pk);
void store_priv_key(const uint8_t* key_data, size_t key_len);
void save_rsa_private_key(mbedtls_pk_context *pk);
void test_private_key_encrypted_write(const esp_partition_t *partition, const unsigned char *original_key, size_t key_len);
void get_message_digest(unsigned char message, size_t message_len);

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
    // mbedtls_pk_init(&rsa);
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
      printf("\nKey pair generated successfully!\n");
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
    printf("Key length is ");
    printf("Key length is %d bytes.\n", mbedtls_rsa_get_len(mbedtls_pk_rsa(*pk)));
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


// Test if private key was encrypted and written to the partition
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
        printf("Success: The private key is encrypted on flash.\n");
    }

    free(read_back_data);
}


void get_message_digest(unsigned char message, size_t message_len){

  #define SHA_MODE_REG                  ((DR_REG_SHA_BASE) + 0x00)
}

int main(){
  // Generate CSPRNS
  unsigned char sequence[4];
  get_prns(sequence, sizeof(sequence));
  printf("Random Sequence Generated.");
  
  // Generate RSA key pair and store in RSA context
  printf("Generating key pair...\n");
  mbedtls_pk_context* pk = gen_key_pair();
  test_keys(pk);
  printf("Key pair generated.\n");

  // Encrypts only the private key in its own partition while the rest of the data is plaintext
  printf("Storing private key...\n");
  save_rsa_private_key(pk);
  printf("Private key stored.\n");

  // Generate message digest using SHA-512
  printf("Generating message digest...\n");
  size_t digest_len = sizeof(sequence);
  get_message_digest(sequence, digest_len);
  printf("Message digest generated.\n");
  

  mbedtls_pk_free(pk);
  return 0;
}


void app_main(void)
{
  main();
}