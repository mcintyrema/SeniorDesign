#include "rf_target.h"
#include "rsa_functions.h"

uint8_t authorized_peers[][6] = {
        {0x32, 0xB7, 0xDA, 0x6A, 0xA1, 0x08}, // target COM11, STA
        {0x34, 0xB7, 0xDA, 0x6A, 0xBF, 0xD0},// portable COM10, AP
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // broadcast
        {0x76, 0xCC, 0xCA, 0x3F, 0x70, 0xCC} // port receives from target address
    };

TaskHandle_t sendSeqHandle = NULL;
TaskHandle_t rxSignature = NULL;
SemaphoreHandle_t sendCompleteSemaphore = NULL;

// flags
int signature_received = 1;
int get_key_now = 1;

#define SIGNATURE_SIZE 256 // signature size in bytes
#define CHUNK_SIZE 128     // Incoming packet chunk size
#define PUB_KEY_SIZE 256 // public key size in bytes

uint8_t digital_signature[SIGNATURE_SIZE]; // Buffer to hold the full digital signature
uint8_t public_key[PUB_KEY_SIZE+3];
size_t received_bytes = 0; // Track received packets
unsigned char sequence[4];


void configure_wifi_target(wifi_mode_t mode){
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


void get_mac_address_target(uint8_t *address, wifi_interface_t ifx){
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


void deinitialize_wifi_target(){
  // Deinitialize ESP-NOW if needed
  esp_now_deinit();
  esp_wifi_stop();
  esp_wifi_deinit();
}

  
void connect_to_portable(uint8_t mac_addresses[6]){
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
    configure_wifi_target(WIFI_MODE_APSTA);
    // esp_now_register_send_cb(OnDataSent);
    
    uint8_t *baseMac = malloc(6);

    get_mac_address_target(baseMac, WIFI_IF_STA);

    printf("Peer MAC address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", authorized_peers[1][i]);
        if (i < 5) {
            printf(":"); // Print colon between bytes, but not after the last byte
        }
    }
    printf("\n");
    
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE); 
    connect_to_portable(authorized_peers[1]); 
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_now_register_recv_cb(OnDataRecv);
    esp_now_register_send_cb(OnDataSent);

    free(baseMac);
}


void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  printf("\r\nSequence Packet Send Status:\t");
  printf(status == ESP_NOW_SEND_SUCCESS ? "Delivered Successfully\n" : "Delivery Fail\n");
  return;
}


void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len){
  // Print the MAC address of the sender
  printf("Data length: %d\n", len);
  signature_received = 0;

  if(get_key_now == 0){
    // Check if public key received
    if (received_bytes + len <= (PUB_KEY_SIZE+3)) {
      // Copy the incoming chunk into the digital_signature buffer
      memcpy(public_key + received_bytes, incomingData, len);
      received_bytes += len;
      printf("Total public key bytes received so far: %zu\n", received_bytes);
    } 
    // Check if received the entire signature
    if(received_bytes == (PUB_KEY_SIZE+3)) {
      printf("Full public key received.\n");
      // Reset for public key
      received_bytes = 0;
      process_digital_signature(digital_signature, SIGNATURE_SIZE, public_key, 259);
    }
  }
  else{
    // Check if the incoming data will fit in the buffer
    if (received_bytes + len <= SIGNATURE_SIZE) {
      // Copy the incoming chunk into the digital_signature buffer
      memcpy(digital_signature + received_bytes, incomingData, len);
      received_bytes += len;
      printf("Total bytes received so far: %zu\n", received_bytes);
    } 

    // Check if received the entire signature
    if(received_bytes == SIGNATURE_SIZE) {
      printf("Full digital signature received.\n");
      // Reset for public key
      received_bytes = 0;
      get_key_now = 0;
    }
  }

  return;
}


void process_digital_signature(uint8_t *signature, size_t sig_len, uint8_t *pub_key, size_t pk_len) {
  printf("Processing digital signature...\n");

  // Initialize mbedtls_mpi structure for the signature
  mbedtls_mpi mpi_signature;
  mbedtls_mpi_init(&mpi_signature);

  // Read the signature from the buffer into mbedtls_mpi format
  mbedtls_mpi_read_binary(&mpi_signature, signature, sig_len);
  printf("Size of digital signature: %d bytes\n", mbedtls_mpi_size(&mpi_signature));

  // Extract N and E from public_key[]
  size_t n_size = 256;  // Modulus size in bytes 
  size_t e_size = pk_len - n_size;  // Exponent size 

  // Create mbedtls_mpi structures to hold N and E
  mbedtls_mpi N;
  mbedtls_mpi E;
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);

  uint8_t *modulus = malloc(n_size);
  memcpy(modulus, pub_key, n_size);
  mbedtls_mpi_read_binary(&N, modulus, n_size);
  printf("Size of N: %d bytes\n", mbedtls_mpi_size(&N));

  // Extract exponent (E) from the public_key array (next e_size bytes)
  uint8_t *exponent = malloc(e_size);
  memcpy(exponent, pub_key + n_size, e_size);
  mbedtls_mpi_read_binary(&E, exponent, e_size);
  printf("Size of E: %d bytes\n", mbedtls_mpi_size(&E));

  // Verify Signature
  // Get hash of generated prns
  size_t sequence_len = sizeof(sequence);
  unsigned char *message_digest = malloc(SHA512_DIGEST_LENGTH);
  get_message_digest(&sequence, sequence_len, message_digest);

  verify_dig_sig(&N, &E, &mpi_signature, message_digest);


  // Free resources
  mbedtls_mpi_free(&mpi_signature);
  printf("Digital signature processing completed.\n");
  if(valid_signature == 0){
      printf("Send 0 signal\n");
      vTaskDelay(pdMS_TO_TICKS(2000));
      deinitialize_wifi_target();
  }
  else{
      printf("Send 1 signal\n");
      vTaskDelay(pdMS_TO_TICKS(2000));
      deinitialize_wifi_target();
  }
}


void send_sequence_task() {
  // Generate CSPRNS
  printf("Generating random sequence...\n");
  // unsigned char sequence[4];
  get_prns(sequence, sizeof(sequence));
  printf("Random sequence generated successfully.\n");

  vTaskDelay(pdMS_TO_TICKS(2000));
  esp_err_t result = esp_now_send(authorized_peers[1], (uint8_t *) &sequence, sizeof(sequence));

  if (result == ESP_OK) {
    printf("\nSent Successfully.\n");
    xSemaphoreGive(sendCompleteSemaphore);
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



void receive_sig_task(){
  printf("Waiting for incoming data...\n");

  // Wait until message
  while (signature_received == 1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
  // delete task when message received
  vTaskDelete(rxSignature);
}
