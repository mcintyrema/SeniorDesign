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
#include <esp_wifi.h>
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_now.h"
/* COM FILES */
#include "rsa_functions.h"
#include "rf_com.h"


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

uint8_t broadcast_address[] = {0x34, 0xB7, 0xDA, 0x6A, 0xBF, 0xD0};

typedef struct struct_message {
    float temp;
} struct_message;
char success;

struct_message test_data; 
esp_now_peer_info_t peerInfo;

void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  printf("\r\nDelivery Status: ");
  printf(status == ESP_NOW_SEND_SUCCESS ? "Deliverd Successfully" : "Delivery Fail");
  if (status ==0){
    success = "Delivery Success :)";
  }
  else{
    success = "Delivery Fail :(";
  }
}

void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len) {
  memcpy(&test_data, incomingData, sizeof(test_data));
  printf("data receviced");
}


void app_main_target(void)
{
//   main();
    configure_wifi_station(WIFI_MODE_STA);
    if (esp_now_init() != ESP_OK) {
    printf("Error initializing ESP-NOW");
    return;
  }
  esp_now_register_send_cb(OnDataSent);

  memcpy(peerInfo.peer_addr, broadcast_address, 6);
  peerInfo.channel = 0; 
  peerInfo.encrypt = 0;
       
  if (esp_now_add_peer(&peerInfo) != ESP_OK){
    printf("Failed to add peer");
    return;
  }
  esp_now_register_recv_cb(OnDataRecv);

    while(1){
        float fake_sequence = 2.45;
        esp_err_t result = esp_now_send(broadcast_address, (uint8_t *) &fake_sequence, sizeof(fake_sequence));
   
        if (result == ESP_OK) {
            printf("Sent Successfullt");
        }
        else {
            printf("Getiing Error while sending the data");
        }
        vTaskDelay(3000);
    }

    esp_wifi_set_max_tx_power(84);
    
}









uint8_t broadcast_address_target[] = {0x32, 0xB7, 0xDA, 0x6A, 0xA1, 0x08};

// typedef struct struct_message {
//     float temp;
// } struct_message;
char success;

struct_message test_data_port; 
esp_now_peer_info_t peerInfo;
void OnDataSent_port(const uint8_t *mac_addr, esp_now_send_status_t status) {
  printf("\r\nDelivery Status:\t");
  printf(status == ESP_NOW_SEND_SUCCESS ? "Delivery Successfully" : "Delivery Fail");
  if (status ==0){
    success = "Delivery Success :)";
  }
  else{
    success = "Delivery Fail :(";
  }
}

void OnDataRecv_port(const uint8_t * mac, const uint8_t *incomingData, int len) {
  memcpy(&test_data_port, incomingData, sizeof(test_data_port));
  printf("received data");
}

void app_main_port(void)
{
//   main();
    configure_wifi_station(WIFI_MODE_STA);
    if (esp_now_init() != ESP_OK) {
    printf("Error initializing ESP-NOW");
    return;
  }
  esp_now_register_send_cb(OnDataSent_port);

  memcpy(peerInfo.peer_addr, broadcast_address_target, 6);
  peerInfo.channel = 0; 
  peerInfo.encrypt = 0;
       
  if (esp_now_add_peer(&peerInfo) != ESP_OK){
    printf("Failed to add peer");
    return;
  }
  esp_now_register_recv_cb(OnDataRecv_port);

    while(1){
        float fake_sequence = 444;
        esp_err_t result = esp_now_send(broadcast_address_target, (uint8_t *) &fake_sequence, sizeof(fake_sequence));
   
        if (result == ESP_OK) {
            printf("Sent Successfully");
        }
        else {
            printf("Getiing Error while sending the data");
        }
        vTaskDelay(3000);
    }

    esp_wifi_set_max_tx_power(84);
    
}



void app_main(){
    // app_main_target();
    app_main_port();
}