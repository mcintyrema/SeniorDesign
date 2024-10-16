#ifndef RF_COM
#define RF_COM

void configure_wifi_station(wifi_mode_t mode);
void get_mac_address(uint8_t *address, wifi_interface_t ifx);
void deinitialize_wifi();
void connect_to_peer(uint8_t mac_addresses[6]);
void format_data_to_send(unsigned char *message, uint8_t mac_address[6]);

void com_target_setup();
void com_portable_setup();
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status);
void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len);
void OnDataSent_port(const uint8_t *mac_addr, esp_now_send_status_t status) ;
void OnDataRecv_port(const uint8_t * mac, const uint8_t *incomingData, int len);
void receive_sequence_task();
void send_sequence_task();

extern uint8_t authorized_mac_addresses[][6];

#endif