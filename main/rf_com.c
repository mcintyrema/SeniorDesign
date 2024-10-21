/* C libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
/* ESP*/
#include "esp_partition.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include <esp_wifi.h>
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_now.h"
#include <esp_netif.h>
#include "rf_com.h"
#include "rsa_functions.h"

uint8_t authorized_mac_addresses[][6] = {
        {0x32, 0xB7, 0xDA, 0x6A, 0xA1, 0x08}, // target COM11, STA
        {0x34, 0xB7, 0xDA, 0x6A, 0xBF, 0xD0},// portable COM10, AP
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // broadcast
        {0x76, 0xCC, 0xCA, 0x3F, 0x70, 0xCC} // port receives from target address
    };

TaskHandle_t sendSeqHandle = NULL;
TaskHandle_t rxHandle = NULL;
TaskHandle_t sequenceHandle = NULL;
TaskHandle_t sendSigHandle = NULL;
TaskHandle_t rxSignature = NULL;

const uint8_t *received_num_sequence = NULL;
size_t received_sequence_length = 0;
bool message_received = false;
bool signature_received = false;
int valid_signature = 0;


void configure_wifi_station(wifi_mode_t mode){
  // Initialize NVS partition storage
  nvs_flash_init();

  // Initialize TCP/IP stack, but no need to start it
  esp_netif_init();
  esp_event_loop_create_default();
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_mode(mode);  // ESP-NOW requires station mode
  esp_wifi_start();  // Start Wi-Fi for ESP-NOW functionality

  // Initialize ESP-NOW
  int ret = esp_now_init();
  if (ret != ESP_OK) {
    printf("ESP-NOW initialization failed\n");
    return;
  }
}


void get_mac_address(uint8_t *address, wifi_interface_t ifx){
    // Get MAC address
    int ret = esp_wifi_get_mac(ifx, address);
    if (ret == ESP_OK) {
        printf("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", 
                address[0], address[1], address[2], 
                address[3], address[4], address[5]);
    } else {
        printf("Failed to read MAC address\n");
    }
}


void deinitialize_wifi(){
  // Deinitialize ESP-NOW if needed
  esp_now_deinit();
  esp_wifi_stop();
  esp_wifi_deinit();
}

  
void connect_to_peer(uint8_t mac_addresses[6]){
  // Set peer info
  struct esp_now_peer_info peerInfo;
  // Get the MAC address string
  memcpy(peerInfo.peer_addr, mac_addresses, 6);
  peerInfo.channel = 1; // 1, 6, or 11
  peerInfo.encrypt = 0;
  // esp_now_add_peer(&peerInfo);
  esp_err_t result = esp_now_add_peer(&peerInfo);
  if (result == ESP_OK) {
    printf("Peer confirmed.\n");
  }
  else {
    printf("Peer error.\n");
  }

}


void com_target_setup(){
    configure_wifi_station(WIFI_MODE_APSTA);
    // esp_now_register_recv_cb(OnDataRecv);
    esp_now_register_send_cb(OnDataSent);
    
    uint8_t *baseMac = malloc(6);
    get_mac_address(baseMac, WIFI_IF_STA);

    printf("Peer MAC address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", authorized_mac_addresses[1][i]);
        if (i < 5) {
            printf(":"); // Print colon between bytes, but not after the last byte
        }
    }
    printf("\n");
    
    esp_wifi_set_channel(1, 6); 
    connect_to_peer(authorized_mac_addresses[1]); 
    esp_now_register_recv_cb(OnDataRecv);
    // esp_now_register_send_cb(OnDataSent);
}


void com_portable_setup(){
    configure_wifi_station(WIFI_MODE_APSTA); 
    // esp_now_register_recv_cb(OnDataRecv_port);
    esp_now_register_send_cb(OnDataSent_port);

    uint8_t *baseMac = malloc(6);
    get_mac_address(baseMac, WIFI_IF_STA);

    printf("Peer MAC address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", authorized_mac_addresses[0][i]);
        if (i < 5) {
            printf(":"); // Print colon between bytes, but not after the last byte
        }
    }
    printf("\n");

    esp_wifi_set_channel(1, 6); 
    connect_to_peer(authorized_mac_addresses[0]); //target address
    // esp_now_register_send_cb(OnDataSent_port);
    esp_now_register_recv_cb(OnDataRecv_port);
}


void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  printf("\r\nSequence Packet Send Status:\t");
  printf(status == ESP_NOW_SEND_SUCCESS ? "Delivered Successfully\n" : "Delivery Fail\n");
  return;
}


void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len){
  // Print the MAC address of the sender
  printf("Data received from: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X:", mac[i]);
    }
    printf("\n");
    
    printf("Data length: %d\n", len);
    printf("Received data: ");
    for (int i = 0; i < len; i++) {
        printf("%02X ", incomingData[i]);
    }
    printf("\n");
  signature_received = true;
  return;
}


void OnDataSent_port(const uint8_t *mac_addr, esp_now_send_status_t status){
  printf("\r\nDigital Signature Packet Send Status:\t");
  printf(status == ESP_NOW_SEND_SUCCESS ? "Delivered Successfully\n" : "Delivery Fail\n");
  return;
}

void OnDataRecv_port(const uint8_t * mac, const uint8_t *incomingData, int len) {  
  // Print the MAC address of the sender
  printf("Received message from: ");
  for (int i = 0; i < ESP_NOW_ETH_ALEN; i++) {
      printf("%02X", mac[i]);
      if (i < ESP_NOW_ETH_ALEN - 1) {
          printf(":");
      }
  }
  printf("\n");

  // Print the received data
  printf("Data received: ");
  for (int i = 0; i < len; i++) {
      printf("%02X ", incomingData[i]);
  }
  printf("\n");

  printf("Signing Sequence...\n");
  received_num_sequence = (uint8_t *) malloc(len);
  memcpy(received_num_sequence, incomingData, len);
  message_received = true;
  
  
  BaseType_t result = xTaskCreate(handle_sequence_task, "Handle Sequence Task", 4096, NULL, 2, &sequenceHandle);
  if (result == pdPASS) {
      printf("Handle Sequence task created successfully.\n");
  } else {
      printf("Failed to create signing task.\n");
  }
  return;
}


void send_sequence_task() {
  // Generate CSPRNS
  printf("Generating random sequence...\n");
  unsigned char sequence[4];
  get_prns(sequence, sizeof(sequence));
  printf("Random sequence generated successfully.\n");

  vTaskDelay(pdMS_TO_TICKS(2000));
  esp_err_t result = esp_now_send(authorized_mac_addresses[1], (uint8_t *) &sequence, sizeof(sequence));

  if (result == ESP_OK) {
    printf("\nSent Successfully.\n");
  } else {
    printf("Error while sending the data.\n");
  }

  // Print the sent data
  printf("Data sent: ");
  for (int i = 0; i < sizeof(sequence); i++) {
      printf("%02X ", sequence[i]);
  }
  vTaskDelete(NULL);
}


void receive_sequence_task() {
    printf("Waiting for incoming data...\n");
    // Wait until message
    while (!message_received) {
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
    // delete task when message received
    vTaskDelete(rxHandle);
}


void handle_sequence_task() {
  // Process sequence
  printf("Sequence to be signed: ");
  for (int i = 0; i < sizeof(received_num_sequence); i++) {
      printf("%02X ", received_num_sequence[i]);
  }
  printf("\n");

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
  unsigned char sequence[4];
  memcpy(sequence, received_num_sequence, sizeof(received_num_sequence));
  size_t sequence_len = sizeof(sequence);
  unsigned char *message_digest = malloc(SHA512_DIGEST_LENGTH);
  get_message_digest(sequence, sequence_len, message_digest);
  test_hash(message_digest, SHA512_DIGEST_LENGTH);
  printf("Message digest generated successfully.\n");

  // Generate digital signature
  printf("Generating digital signature...\n");
  mbedtls_mpi digital_signature;
  mbedtls_mpi_init(&digital_signature); 
  get_digital_sig(pk, message_digest, &digital_signature);
  printf("Digital signature generated successfully.\n");

  mbedtls_pk_free(pk);
  free(message_digest);

  vTaskDelay(pdMS_TO_TICKS(2000));
  BaseType_t result = xTaskCreate(send_dig_sig, "Send Signature Task", 4096, &digital_signature, 3, &sendSigHandle);
  if (result == pdPASS) {
      printf("Signing task created successfully.\n");
  } else {
      printf("Failed to create signing task.\n");
  }
}

void send_dig_sig(void *const pvParameters){
  vTaskDelete(sequenceHandle);
  printf("Sending digital signature...\n");

  // Send digital signature to target device
  mbedtls_mpi *signature = (mbedtls_mpi *)pvParameters;
  size_t digital_signature_size = mbedtls_mpi_size(signature);
  unsigned char *digital_signature_bytes = malloc(digital_signature_size);
  mbedtls_mpi_write_binary(signature, digital_signature_bytes, digital_signature_size);

  // Packetize digital signature
  for (size_t offset = 0; offset < digital_signature_size; offset += 128) {
    size_t chunk_size = (offset + 128 <= digital_signature_size) ? 128 : (digital_signature_size - offset);
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_err_t result = esp_now_send(authorized_mac_addresses[0], (const uint8_t *)digital_signature_bytes + offset, chunk_size);
    
    if (result != ESP_OK) {
      printf("Error sending chunk. Trying again...\n");
      vTaskDelay(pdMS_TO_TICKS(2000));
      result = esp_now_send(authorized_mac_addresses[0], (const uint8_t *)digital_signature_bytes + offset, chunk_size);
      if (result != ESP_OK) {
        printf("Error sending chunk.\n");
        return;
      }
      else{
        printf("Sent signature successfully\n");
      }
    }
    else{
      printf("Sent signature successfully\n");
    }
    
  }
  free(digital_signature_bytes);
  vTaskDelete(NULL);
}


void receive_sig_task(){
  printf("Waiting for incoming data...\n");

    // Wait until message
    while (!signature_received) {
      printf("go");
      vTaskDelay(pdMS_TO_TICKS(1000));
      printf("still running");
    }
    // delete task when message received
    vTaskDelete(rxSignature);
}