/**
 * @file gs_uhf.hpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.08.03
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef GS_UHF_HPP
#define GS_UHF_HPP

#include <stdint.h>
#include <si446x.h>
#include "network.hpp"

// #define UHF_NOT_CONNECTED_DEBUG

#define SERVER_POLL_RATE 5 // Once per this many seconds
#define SEC *1000000
#define RECV_TIMEOUT 15
#define RADIO_DEVICE_NAME "my_device"

#define NACK_NO_UHF 0x756866 // Roof UHF says it cannot access UHF communications.

#define PIN_TR 16 // RPi GPIO bcm23
#define PIN_PA 18 // RPi GPIO bcm24

#define UHF_RSSI 0

#define SW_UPD_FN_SIZE 20

/// From SPACE-HAUC/uhf_gst ///
#define GST_MAX_PAYLOAD_SIZE 56
#define GST_MAX_PACKET_SIZE 64
#define GST_GUID 0x6f35
#define GST_TERMINATION 0x0d0a // CRLF
typedef struct __attribute__((packed))
{
    uint16_t guid;
    uint16_t crc;
    uint8_t payload[GST_MAX_PAYLOAD_SIZE];
    uint16_t crc1;
    uint16_t termination;
} gst_frame_t;
#define GST_MAX_FRAME_SIZE sizeof(gst_frame_t)

enum GST_ERRORS
{
    GST_ERROR = -1,            //!< General error
    GST_TOUT = 0,              //!< Operation timed out
    GST_SUCCESS = 1,           //!<
    GST_PACKET_INCOMPLETE = 2, //!< Incomplete data received
    GST_GUID_ERROR = 3,        //!< GUID mismatch
    GST_CRC_MISMATCH = 4,      //!< CRC mismatch
    GST_CRC_ERROR = 5,         //!< Wrong CRC
};
///////////////////////////////

typedef struct
{
    uint8_t inhibit_acs;
} cs_config_uhf_t;

// Sent between GUI Client and UHF.
typedef struct __attribute__((packed))
{
    // From UHF Only
    uint32_t current_packet;
    uint32_t total_packets;
    uint8_t in_progress;    // Boolean
    uint8_t finished;       // Boolean

    // To UHF Only
    uint8_t stage;          // If 1, UHF will look for the file in the frame payload after this struct.
    uint8_t begin;          // If 1, UHF will begin the software update process.
    char filename[20];
} sw_update_info_t;

typedef struct
{
    // uhf_modem_t modem; // Just an int.
    int uhf_initd;
    NetDataClient *network_data;
    bool uhf_ready;
    uint8_t netstat;

    char directory[20] = "sendables/";
    char filename[20];
    bool sw_upd_in_progress;
    int sw_upd_packet;
    uint8_t staged;

    // ACS update requests should be sent automatically during the pass unless the client enables the inhibitor. If the 
    // inhibitor is enabled, it will be re-enabled at the start of the next pass. 
    bool acs_update_inhibitor;
    bool in_pass;

    pthread_mutex_t acs_update_lock;
} global_data_t;

/**
 * @brief Command structure that SPACE-HAUC receives.
 * 
 */
typedef struct __attribute__((packed))
{
    uint8_t mod;
    uint8_t cmd;
    int unused;
    int data_size;
    unsigned char data[46];
} cmd_input_t;

/**
 * @brief Command structure that SPACE-HAUC transmits to Ground.
 * 
 */
typedef struct __attribute__((packed))
{
    uint8_t mod;            // 1
    uint8_t cmd;            // 1
    int retval;             // 4
    int data_size;          // 4
    unsigned char data[46]; // 46
} cmd_output_t;

typedef struct
{
    uint8_t ack; // 0 = NAck, 1 = Ack
    int code;    // Error code or some other info.
} cs_ack_t;      // (N/ACK)

/**
 * @brief Listens for UHF packets from SPACE-HAUC.
 * 
 * @param args 
 * @return void* 
 */
void *gs_uhf_rx_thread(void *args);

/**
 * @brief Listens for NetworkFrames from the Ground Station Network.
 * 
 * @param args 
 * @return void* 
 */
void *gs_network_rx_thread(void *args);

/**
 * @brief Sends UHF-received data to the Ground Station Network Server.
 * 
 * @param thread_data 
 * @param buffer 
 * @param buffer_size 
 */
void gs_network_tx(global_data_t *global_data, uint8_t *buffer, ssize_t buffer_size);

/**
 * @brief Periodically polls the Ground Station Network Server for its status.
 * 
 * Doubles as the GS Network connection watch-dog, tries to restablish connection to the server if it sees that we are no longer connected.
 * 
 * @param args 
 * @return void* 
 */
void *gs_polling_thread(void *args);

/**
 * @brief 
 * 
 * @param global_data 
 * @return int 
 */
int gs_connect_to_server(global_data_t *global_data);

/**
 * @brief 
 * 
 * From:
 * https://github.com/sunipkmukherjee/comic-mon/blob/master/guimain.cpp
 * with minor modifications.
 * 
 * @param socket 
 * @param address 
 * @param socket_size 
 * @param tout_s 
 * @return int 
 */
int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s);

/**
 * @brief Initializes X-Band radio.
 * 
 * see: gst_init()
 * https://github.com/SPACE-HAUC/uhf_gst/blob/4a051f511301f1ff8333d3a960d19ce06a463b11/src/uhf_gst.c
 * 
 * @return int 1 on success, 0 on failure.
 */
int gs_uhf_init(void);

/**
 * @brief 
 * 
 * see: gst_read()
 * https://github.com/SPACE-HAUC/uhf_gst/blob/4a051f511301f1ff8333d3a960d19ce06a463b11/src/uhf_gst.c
 * 
 * @param buf 
 * @param buffer_size 
 * @param rssi 
 * @param gst_done 
 * @return ssize_t 
 */
ssize_t gs_uhf_read(char *buf, ssize_t buffer_size, int16_t *rssi, bool *gst_done);

/**
 * @brief 
 * 
 * see: gst_write()
 * https://github.com/SPACE-HAUC/uhf_gst/blob/4a051f511301f1ff8333d3a960d19ce06a463b11/src/uhf_gst.c
 * 
 * @param buf 
 * @param buffer_size 
 * @param gst_done 
 * @return ssize_t 
 */
ssize_t gs_uhf_write(char *buf, ssize_t buffer_size, bool *gst_done);

/**
 * @brief 
 * 
 * @param args 
 * @return void* 
 */
void *gs_sw_send_file_thread(void *args);

/**
 * @brief 
 * 
 * @param filename 
 * @return ssize_t 
 */
ssize_t gs_sw_get_sent_bytes(const char filename[]);

/**
 * @brief 
 * 
 * @param filename 
 * @param sent_bytes 
 * @return int 
 */
int gs_sw_set_sent_bytes(const char filename[], ssize_t sent_bytes);

// NOTE: Needs to be called every time we want to begin talking to SPACE-HAUC, but haven't had a communication with it for more than a couple minutes.
// void gs_uhf_enable_pipe(void) __attribute__((alias("si446x_en_pipe")));

// TODO: Add new stuff to Makefile so its not undefined reference.

void *gs_acs_update_thread(void *global_data_vp);

#endif // GS_UHF_HPP