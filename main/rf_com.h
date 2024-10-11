#ifndef RF_COM
#define RF_COM

void configure_wifi_station(wifi_mode_t mode);
void get_mac_address(uint8_t *address, wifi_interface_t ifx);
void deinitialize_wifi();
void connect_to_peer(uint8_t mac_addresses[6]);
void format_data_to_send(unsigned char *message, uint8_t mac_address[6]);
void com_target_setup();
void com_portable_setup();
// void recv_data_portable(const uint8_t *mac_addr, const uint8_t *data, int data_len);
void on_data_recv(const esp_now_recv_info_t *recv_info, const uint8_t *data, int data_len);
extern uint8_t authorized_mac_addresses[][6];

#endif