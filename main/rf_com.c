/* C libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

uint8_t authorized_mac_addresses[][6] = {
        {0x32, 0xB7, 0xDA, 0x6A, 0xA1, 0x08}, // target COM11
        {0x34, 0xB7, 0xDA, 0x6A, 0xBF, 0xD0} // portable COM10
    };

void configure_wifi_station(wifi_mode_t mode){
  // Initialize NVS partition storage
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      nvs_flash_erase();
      nvs_flash_init();
  }

  // Initialize TCP/IP stack, but no need to start it
  esp_netif_init();
  esp_event_loop_create_default();
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_mode(mode);  // ESP-NOW requires station mode
  esp_wifi_start();  // Start Wi-Fi for ESP-NOW functionality

  // Initialize ESP-NOW
  ret = esp_now_init();
  if (ret != ESP_OK) {
    printf("ESP-NOW initialization failed\n");
    return;
  }
}


void get_mac_address(uint8_t *address, wifi_interface_t ifx){
    // Get MAC address
    int ret = esp_wifi_get_mac(WIFI_IF_STA, address);
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
  peerInfo.encrypt = 1;
  esp_now_add_peer(&peerInfo);

}


void format_data_to_send(unsigned char *message, uint8_t mac_address[6]){
  typedef struct struct_message {
  unsigned char a[32];
  } struct_message;

  struct struct_message myData;
  size_t message_len = strlen((char *)message);
  memcpy(myData.a, message, message_len);

  // Send message via ESP-NOW
  esp_err_t result = esp_now_send(mac_address, (uint8_t *) &myData, sizeof(myData));
  if (result == ESP_OK) {
    printf("Sending confirmed.\n");
  }
  else {
    printf("Sending error.\n");
  }
}


void com_target_setup(){
    configure_wifi_station(WIFI_MODE_STA);
    
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

    connect_to_peer(authorized_mac_addresses[1]); 
}


void com_portable_setup(){
    configure_wifi_station(WIFI_MODE_AP);

    uint8_t *baseMac = malloc(6);
    get_mac_address(baseMac, WIFI_IF_AP);

    printf("Peer MAC address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", authorized_mac_addresses[0][i]);
        if (i < 5) {
            printf(":"); // Print colon between bytes, but not after the last byte
        }
    }
    printf("\n");

    connect_to_peer(authorized_mac_addresses[0]); //target address
}


void on_data_recv(const esp_now_recv_info_t *recv_info, const uint8_t *data, int data_len) {
    // Print the MAC address of the sender
    printf("Received message from: ");
    for (int i = 0; i < ESP_NOW_ETH_ALEN; i++) {
        printf("%02X", recv_info->src_addr[i]);
        if (i < ESP_NOW_ETH_ALEN - 1) {
            printf(":");
        }
    }
    printf("\n");

    // Print the received data
    printf("Data received: ");
    for (int i = 0; i < data_len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}
