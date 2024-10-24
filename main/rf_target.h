#ifndef RF_TARGET
#define RF_TARGET
/* C libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
/*ESP libraries*/
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

void configure_wifi_target(wifi_mode_t mode);
void get_mac_address_target(uint8_t *address, wifi_interface_t ifx);
void deinitialize_wifi_target();
void connect_to_portable(uint8_t mac_addresses[6]);

void com_target_setup();
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status);
void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len);
void send_sequence_task();
void receive_sig_task();
void process_digital_signature(uint8_t *signature, size_t sig_len, uint8_t *pub_key, size_t pk_len);

extern TaskHandle_t sendSeqHandle;
extern TaskHandle_t rxSignature;
extern uint8_t authorized_mac_addresses[][6];
extern SemaphoreHandle_t sendCompleteSemaphore;
extern SemaphoreHandle_t verifySignatureSemaphore;
extern unsigned char sequence[4];

#endif