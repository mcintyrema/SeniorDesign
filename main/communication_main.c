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
//   printf("Generating digital signature...\n");
//   get_digital_sig(pk, message_digest);
//   printf("Digital signature generated successfully.\n");

  mbedtls_pk_free(pk);
  free(message_digest);
  return 0;
}


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

    vTaskGetInfo(rxSignature, &xTaskDetails2, pdTRUE, eInvalid);
    printTaskState(xTaskDetails2);
}


void app_main_port(void)
{
    com_portable_setup();
    //loop
    xTaskCreate(receive_sequence_task, "Receive Task", 4096, NULL, 1, &rxHandle);
}


void app_main(){
    esp_wifi_set_max_tx_power(84);

    app_main_target();
    // app_main_port();
    
    // vTaskGetInfo(rxSignature, &xTaskDetails, pdTRUE, eInvalid);
    // printTaskState(xTaskDetails);

    // vTaskGetInfo(rxSignature, &xTaskDetails2, pdTRUE, eInvalid);
    // printTaskState(xTaskDetails2);
}