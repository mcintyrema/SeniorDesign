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
// #include "FreeRTOSConfig.h"
#include "freertos/task.h"
#include "esp_err.h"
#include <esp_wifi.h>
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_now.h"
/* COM FILES */
#include "rsa_functions.h"
#include "rf_target.h"
#include "rf_portable.h"

TaskStatus_t xTaskDetails;
TaskStatus_t xTaskDetails2;


void printTaskState(TaskStatus_t xTaskDetails) {
    switch (xTaskDetails.eCurrentState) {
        case eRunning:
            printf("Task is running\n");
            break;
        case eReady:
            printf("Task is ready\n");
            break;
        case eBlocked:
            printf("Task is blocked\n");
            break;
        case eSuspended:
            printf("Task is suspended\n");
            break;
        case eDeleted:
            printf("Task is deleted\n");
            break;
        case eInvalid:
            printf("Task state is invalid\n");
            break;
        default:
            printf("Unknown task state\n");
            break;
    }
}

void app_main_target(void)
{
    sendCompleteSemaphore = xSemaphoreCreateBinary();

    clock_t start_t, end_t;
    double total_t;

    com_target_setup();

    start_t = clock();
    xTaskCreate(send_sequence_task, "Send Task", 8192, NULL, 1, &sendSeqHandle);
    end_t = clock();
    total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
    printf("Total time taken to generate and send sequnece: %f seconds\n", total_t);

    if (xSemaphoreTake(sendCompleteSemaphore, portMAX_DELAY) == pdTRUE) {
        vTaskDelete(sendSeqHandle);
        vTaskDelay(pdMS_TO_TICKS(2000));
        xTaskCreate(receive_sig_task, "Receive Signature Task", 8192, NULL, 5, &rxSignature);
    }

}


void app_main_port(void)
{
    com_portable_setup();
    //loop
    xTaskCreate(receive_sequence_task, "Receive Task", 4096, NULL, 1, &rxHandle);
    vTaskDelay(pdMS_TO_TICKS(60000));
    deinitialize_wifi();
}


void app_main(){
    esp_wifi_set_max_tx_power(84); //21 dBm, 340mA for Tx, 91mA for Rx

    // app_main_port();
    app_main_target();
}