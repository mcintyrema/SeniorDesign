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

int signature_received = 1;
int valid_signature = 0;


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
    // esp_now_register_recv_cb(OnDataRecv);
    esp_now_register_send_cb(OnDataSent);
    
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
    
    esp_wifi_set_channel(1, 6); 
    connect_to_portable(authorized_peers[1]); 
    esp_now_register_recv_cb(OnDataRecv);
    // esp_now_register_send_cb(OnDataSent);
}


void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  printf("\r\nSequence Packet Send Status:\t");
  printf(status == ESP_NOW_SEND_SUCCESS ? "Delivered Successfully\n" : "Delivery Fail\n");
  return;
}


void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len){
  // Print the MAC address of the sender
  printf("Data received from: ");
  //   for (int i = 0; i < 6; i++) {
  //       printf("%02X:", mac[i]);
  //   }
  //   printf("\n");
    
  //   printf("Data length: %d\n", len);
  //   printf("Received data: ");
  //   for (int i = 0; i < len; i++) {
  //       printf("%02X ", incomingData[i]);
  //   }
  //   printf("\n");
  // signature_received = 0;
  // return;
}


void send_sequence_task() {
  // Generate CSPRNS
  printf("Generating random sequence...\n");
  unsigned char sequence[4];
  get_prns(sequence, sizeof(sequence));
  printf("Random sequence generated successfully.\n");

  vTaskDelay(pdMS_TO_TICKS(2000));
  esp_err_t result = esp_now_send(authorized_peers[1], (uint8_t *) &sequence, sizeof(sequence));

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
  // vTaskEndScheduler();
  vTaskDelete(NULL);
}



void receive_sig_task(){
  printf("Waiting for incoming data...\n");
  // Wait until message
  printf("%d", signature_received);
  while (signature_received == 1) {
    printf("%d", signature_received);
    vTaskDelay(pdMS_TO_TICKS(1000));
    printf("still running");
  }
    // delete task when message received
    vTaskDelete(rxSignature);
}
