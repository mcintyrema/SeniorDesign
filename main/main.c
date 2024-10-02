/* C libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
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
#include "esp_mac.h"

/* SHA Accelerator Base Address*/
#define SHA_BASE_REG (0x6003B000)

/* SHA INPUT MESSAGE REGS */
#define SHA_M_0_REG  (SHA_BASE_REG + 0x0080)
#define SHA_M_1_REG  (SHA_BASE_REG + 0x0084)
#define SHA_M_2_REG  (SHA_BASE_REG + 0x0088)
#define SHA_M_3_REG  (SHA_BASE_REG + 0x008C)
#define SHA_M_4_REG  (SHA_BASE_REG + 0x0090)
#define SHA_M_5_REG  (SHA_BASE_REG + 0x0094)
#define SHA_M_6_REG  (SHA_BASE_REG + 0x0098)
#define SHA_M_7_REG  (SHA_BASE_REG + 0x009C)
#define SHA_M_8_REG  (SHA_BASE_REG + 0x00A0)
#define SHA_M_9_REG  (SHA_BASE_REG + 0x00A4)
#define SHA_M_10_REG (SHA_BASE_REG + 0x00A8)
#define SHA_M_11_REG (SHA_BASE_REG + 0x00AC)
#define SHA_M_12_REG (SHA_BASE_REG + 0x00B0)
#define SHA_M_13_REG (SHA_BASE_REG + 0x00B4)
#define SHA_M_14_REG (SHA_BASE_REG + 0x00B8)
#define SHA_M_15_REG (SHA_BASE_REG + 0x00BC)

// SHA result registers 
#define SHA_H_0_REG  (SHA_BASE_REG + 0x0040)
#define SHA_H_1_REG  (SHA_BASE_REG + 0x0044)
#define SHA_H_2_REG  (SHA_BASE_REG + 0x0048)
#define SHA_H_3_REG  (SHA_BASE_REG + 0x004C)
#define SHA_H_4_REG  (SHA_BASE_REG + 0x0050)
#define SHA_H_5_REG  (SHA_BASE_REG + 0x0054)
#define SHA_H_6_REG  (SHA_BASE_REG + 0x0058)
#define SHA_H_7_REG  (SHA_BASE_REG + 0x005C)
#define SHA_H_8_REG  (SHA_BASE_REG + 0x0060)
#define SHA_H_9_REG  (SHA_BASE_REG + 0x0064)
#define SHA_H_10_REG (SHA_BASE_REG + 0x0068)
#define SHA_H_11_REG (SHA_BASE_REG + 0x006C)
#define SHA_H_12_REG (SHA_BASE_REG + 0x0070)
#define SHA_H_13_REG (SHA_BASE_REG + 0x0074)
#define SHA_H_14_REG (SHA_BASE_REG + 0x0078)
#define SHA_H_15_REG (SHA_BASE_REG + 0x007C)
// SHA REGISTERS
#define SHA_MODE_REG          (SHA_BASE_REG + 0x0000)
#define SHA_DMA_BLOCK_NUM_REG (SHA_BASE_REG + 0x000C)
#define SHA_BUSY_REG          (SHA_BASE_REG + 0x0018)
#define SHA_DMA_START_REG     (SHA_BASE_REG + 0x001C)
#define SHA_BLOCK_SIZE 128 

// RSA REGISTERS
#define RSA_BASE_REG (0x6003C000)
#define RSA_MODE_REG (RSA_BASE_REG + 0x0804)
#define RSA_M_MEM (RSA_BASE_REG + 0x01FF)
#define RSA_Z_MEM (RSA_BASE_REG + 0x03FF)
#define RSA_Y_MEM (RSA_BASE_REG + 0x05FF)
#define RSA_X_MEM (RSA_BASE_REG + 0x07FF)
#define RSA_MODEXP_START_REG (RSA_BASE_REG + 0x080C)
#define RSA_IDLE_REG (RSA_BASE_REG + 0x0818)
#define RSA_CONSTANT_TIME_REG (RSA_BASE_REG + 0x0820)





//Prototypes
int miller_rabin_test(mbedtls_mpi* n, mbedtls_mpi* d);
void get_prns(unsigned char *randomBlock, size_t size);
mbedtls_pk_context* gen_key_pair();
int check_primality(mbedtls_mpi *n, int iters);
void test_keys(mbedtls_pk_context *pk);
void store_priv_key(const uint8_t* key_data, size_t key_len);
void save_rsa_private_key(mbedtls_pk_context *pk);
void test_private_key_encrypted_write(const esp_partition_t *partition, const unsigned char *original_key, size_t key_len);
uint8_t get_message_digest(unsigned char message, size_t message_len);
unsigned char* pad_message(const unsigned char *message, size_t message_len, size_t *padded_len);
void parse_and_write_sha_message(const unsigned char *padded_message, size_t padded_len);
uint8_t test_hash(uint8_t *message_digest, size_t length);
void get_digital_sig(mbedtls_pk_context* pk, uint8_t message_digest);

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
        printf("The private key is encrypted on flash.\n");
    }

    free(read_back_data);
}


unsigned char* pad_message(const unsigned char *message, size_t message_len, size_t *padded_len) {
    const size_t block_size = 128; // SHA-512 uses a block size of 1024 bits (128 bytes)
    const size_t length_field_size = 16; // 128 bits = 16 bytes

    // Calculate total length after padding
    size_t total_len = message_len + 1 + length_field_size; // +1 for '1' bit, +length_field_size for the 128-bit length
    size_t padding_len = (block_size - (total_len % block_size)) % block_size; // Amount of padding to add
    total_len += padding_len; // Total length includes the padding

    // Allocate memory for the padded message
    unsigned char* padded_message = malloc(total_len);
    if (!padded_message) return NULL;

    // Append the '1' bit (0x80)
    padded_message[message_len] = 0x80;

    // Append k zero bits
    memset(padded_message + message_len + 1, 0, padding_len);

    // Append the original message length (in bits)
    uint64_t original_length_bits = message_len * 8; // Convert length to bits
    for (int i = 0; i < length_field_size; i++) {
        padded_message[total_len - length_field_size + i] = (original_length_bits >> (56 - (i * 8))) & 0xFF;
    }

    // Set the padded length to the output parameter
    *padded_len = total_len;

    return padded_message;
}


void parse_and_write_sha_message(const unsigned char *padded_message, size_t padded_len) {
    // Each block is 128 bytes (1024 bits)
    const size_t block_size = 128; // 1024 bits = 128 bytes

    // Loop through each 1024-bit (128-byte) block
    for (size_t block_index = 0; block_index < padded_len / block_size; block_index++) {
        const unsigned char *block = padded_message + (block_index * block_size);

        // Each block consists of 16 words of 64 bits (8 bytes)
        for (int i = 0; i < 16; i++) {
            // Extract the 64-bit word
            uint64_t word = *(uint64_t*)(block + (i * 8)); // Each word is 8 bytes

            // Split into two 32-bit parts
            uint32_t high = (uint32_t)(word >> 32);  // Most significant 32 bits
            uint32_t low = (uint32_t)(word & 0xFFFFFFFF); // Least significant 32 bits

            // Write to the corresponding registers
            REG_WRITE(SHA_M_0_REG + (i * 4), high); // Write high part
            REG_WRITE(SHA_M_0_REG + (i * 4) + 4, low); // Write low part
        }
    }
}


uint8_t get_message_digest(unsigned char message, size_t message_len){
  REG_WRITE(SHA_MODE_REG, 4); // Set mode to SHA-512

  // Calculate the number of 128-byte blocks (SHA-512 processes blocks in 128-byte blocks)
  size_t num_blocks = (message_len + SHA_BLOCK_SIZE - 1) / SHA_BLOCK_SIZE;
  // Set the number of message blocks to process
  REG_WRITE(SHA_DMA_BLOCK_NUM_REG, num_blocks);

  // Padding
  size_t padded_len;
  unsigned char *padded_message = pad_message(message, message_len, &padded_len);
  // Parsing and write message to appropriate registers
  parse_and_write_sha_message(padded_message, padded_len);

  REG_WRITE(SHA_DMA_START_REG, 1);
  while (REG_READ(SHA_BUSY_REG) != 0) {}

  uint32_t hash[16];

  //////////// FIX THIS - Currently printing all zeros /////////////////////
  for (int i = 0; i < 16; i++) {
    hash[i] = REG_READ(SHA_H_0_REG + (i *4)); // Read the hash by adding 4 to address
  }

  uint8_t full_hash[64]; // 512 bits = 64 bytes
  for (int i = 0; i < 16; i++) {
      full_hash[i * 4 + 0] = (hash[i] >> 24) & 0xFF;
      full_hash[i * 4 + 1] = (hash[i] >> 16) & 0xFF;
      full_hash[i * 4 + 2] = (hash[i] >>  8) & 0xFF;
      full_hash[i * 4 + 3] = (hash[i] >>  0) & 0xFF;
  }

  test_hash(full_hash, sizeof(hash));
  return full_hash;
}


uint8_t test_hash(uint8_t *message_digest, size_t length) {
    printf("Message Digest Length: %zu bytes\n", length);
    for (size_t i = 0; i < length; i++) {
      printf("%02x", message_digest[i]);  // Print each byte as a hex value
    }
    printf("\n");

    return message_digest;
}


void get_digital_sig(mbedtls_pk_context* pk, uint8_t message_digest){
  // Extract core parameters of RSA key
  mbedtls_mpi P, Q, N, D, E;
  mbedtls_mpi_init(&P); 
  mbedtls_mpi_init(&Q);
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&D);
  mbedtls_mpi_init(&E);
  mbedtls_rsa_export(mbedtls_pk_rsa(*pk), &N, &P, &Q, &D, &E);

  // Generate digital signature S = m^d mod n, m<n
  //Write (N 32 − 1) to the RSA_MODE_REG register. N=2048
  REG_WRITE(RSA_MODE_REG, (2048/32 - 1));

}


int main(){
  // Generate CSPRNS
  printf("Generating random sequence...\n");
  unsigned char sequence[4];
  get_prns(sequence, sizeof(sequence));
  printf("Random sequence generated successfully.\n");
  
  // Generate RSA key pair and store in RSA context
  printf("Generating key pair...\n");
  mbedtls_pk_context* pk = gen_key_pair();
  test_keys(pk);
  printf("Key pair generated successfully.\n");

  // Encrypts only the private key in its own partition while the rest of the data is plaintext
  printf("Storing private key...\n");
  save_rsa_private_key(pk);
  printf("Private key stored successfully.\n");

  // Generate message digest using SHA-512
  printf("Generating message digest...\n");
  size_t digest_len = sizeof(sequence);
  uint8_t message_digest = get_message_digest(sequence, digest_len);
  printf("Message digest generated successfully.\n");

  // Generate digital signature S = m^d mod n, m<n
  printf("Generating digital signature...\n");
  get_digital_sig(pk, message_digest);
  printf("Digital signature generated successfully.\n");

  
  mbedtls_pk_free(pk);
  return 0;
}


void app_main(void)
{
  main();
}