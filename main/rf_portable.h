#ifndef RF_PORTABLE
#define RF_PORTABLE

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
#include "mbedtls/bignum.h"

void configure_wifi_station(wifi_mode_t mode);
void get_mac_address(uint8_t *address, wifi_interface_t ifx);
void deinitialize_wifi();
void connect_to_peer(uint8_t mac_addresses[6]);

void com_portable_setup();
void OnDataSent_port(const uint8_t *mac_addr, esp_now_send_status_t status) ;
void OnDataRecv_port(const uint8_t * mac, const uint8_t *incomingData, int len);
void receive_sequence_task();
void handle_sequence_task();
void send_dig_sig(void *const pvParameters);
void send_pub_key();

extern TaskHandle_t rxHandle;
extern TaskHandle_t sequenceHandle;
extern const uint8_t *received_num_sequence;
extern uint8_t authorized_mac_addresses[][6];

#endif