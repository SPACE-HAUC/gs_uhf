/**
 * @file sw_update_packdef.h
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2021-05-09
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef _SW_UPD_PACKDEF_H
#define _SW_UPD_PACKDEF_H
#ifdef __cplusplus
// extern "C"
// {
#endif

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

// Command IDs indicating that a packet is a START/RESUME primer, DATA packet, or CONF header.
#define SW_UPD_SRID 0x20
#define SW_UPD_DTID 0x1f
#define SW_UPD_CFID 0x1e

// Total packet size not to exceed 56 bytes, including info and data. Previously this was 64 bytes, but the GUID and CRC was offloaded to be handled by the UHF module in a UHF Communication Frame.
#define SW_UPD_PACKET_SIZE 56
#define SW_UPD_DATA_SIZE_MAX (SW_UPD_PACKET_SIZE - sizeof(sw_upd_data_t))

#define SW_UPD_MAX_SEND_ATTEMPTS 5
#define SW_UPD_MAX_RECV_ATTEMPTS 100

#define SW_UPD_GS_SLEEP_TIME 1 // 0.1 s
#define SW_UPD_SH_SLEEP_TIME 1 // 0.1 s

#define SW_UPD_HASH_SIZE 32
#define SW_UPD_FN_SIZE 20

typedef enum RET_ERR
{
    ERR_FN_NULL = -10,
    ERR_FN_SIZE,
    ERR_BIN_DNE,
    ERR_FILE_OPEN,
    ERR_CONFUSED
};

typedef enum MODE
{
    primer = 0,
    data,
    transfer_complete,
    confirmation,
    finish
} sw_upd_mode;

typedef enum REQ_PKT
{
    REQ_PKT_RESEND = -2,
    REQ_PKT_AFFIRM = -1
};

/**
 * @brief Primer sent prior to sending data packets.
 * 
 * The START/RESUME primer is sent from the Ground Station to SPACE-HAUC
 * to indicate that either a new file's data will begin transferring or
 * a partially transmitted file will resume its transfer.
 */
typedef struct __attribute__((packed))
{
    char cmd;
    char filename[SW_UPD_FN_SIZE];
    uint8_t fid;
    int sent_bytes;  // How many bytes have been sent thus far (0 for START, >0 for RESUME).
    int total_bytes; // Total expected bytes for the complete file.
} sw_upd_startresume_t;

/**
 * @brief Reply sent after receiving a START/RESUME primer.
 * 
 * The START/RESUME reply is send from SPACE-HAUC to the Ground Station
 * to indicate that SPACE-HAUC has received a START/RESUME primer and is
 * prepared to begin receiving data.
 */
typedef struct __attribute__((packed))
{
    char cmd;
    char filename[SW_UPD_FN_SIZE];
    uint8_t fid;
    int recv_bytes;
    int total_packets; // Total expected packets for the complete file.
} sw_upd_startresume_reply_t;

/**
 * @brief Header sent as part of a data packet.
 * 
 * The DATA header is attached to the beginning of a packet containing data.
 * It provides information on the data and the transfer.
 */
typedef struct __attribute__((packed))
{
    char cmd;
    int packet_number;
    int total_bytes;
    uint8_t data_size;
} sw_upd_data_t;

/**
 * @brief Reply sent after receiving a data packet.
 * 
 * The DATA reply is sent after receiving a data packet. It contains information
 * indicating whether the packet was good or bad. Bad packets could be caused
 * by a variety of factors and could take many forms, but the response will
 * always be to resend the last packet.
 */
typedef struct __attribute__((packed))
{
    char cmd;
    int packet_number;
    int total_packets;
    uint8_t received; // Essentially a boolean. This is the N/ACK. If NACK, send again.
} sw_upd_data_reply_t;

/**
 * @brief 
 * 
 */
typedef struct __attribute__((packed))
{
    char cmd;
    int packet_number;
    int total_packets;
    char hash[SW_UPD_HASH_SIZE];
} sw_upd_conf_t;

/**
 * @brief 
 * 
 */
typedef struct __attribute__((packed))
{
    char cmd;
    int request_packet;
    int total_packets;
    char hash[SW_UPD_HASH_SIZE];
} sw_upd_conf_reply_t;

// If something writes successfully and then reads a 0x0 aka REPT (repeat / send-again command), it should immediately re-write its last transmission.
// If something reads and gets negative value from UHF (error) then it should reply with a REPT command and await what it expected in the first place.
// If UHF times out it returns a 0.
// If GS times out "it should write something", if SH times out "it should wait to read again"
// If error
static char rept_cmd[] = {0x0, 0x40, 0x78, 0x02, 0x78};

typedef struct __attribute__((packed))
{
    char buf[3];
} sw_upd_eof;

/**
 * @brief Calculate the MD5 hash of the given file.
 * 
 * @param fname Full path to file.
 * @param hash Pointer to where hash is stored.
 * @param hashlen Length of memory for hash storage (minimum 32 bytes).
 * @return int Positive on success, negative on failure.
 */
static int checksum_md5(const char *fname, char *hash, ssize_t hashlen)
{
    int retval = 0;
    uint rdsz = 0;
    char cmd[512];
    char buf[32];
    FILE *fp = NULL;

    if (fname == NULL)
    {
        printf("No valid file specified\n");
        retval = -1;
        goto hash_exit;
    }
    if (hash == NULL)
    {
        printf("hash pointer is null\n");
        retval = -1;
        goto hash_exit;
    }
    if (hashlen < 32)
    {
        printf("Not enough memory for hash storage\n");
        retval = -1;
        goto hash_exit;
    }

    snprintf(cmd, sizeof(cmd), "md5sum %s", fname);
    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        printf("Could not open pipe\n");
        perror("hash pipe");
        retval = -1;
        goto hash_cleanup;
    }

    rdsz = fread(buf, 1, sizeof(buf), fp);

    if (rdsz < sizeof(buf))
    {
        printf("Hash size read %d bytes instead of %d bytes\n", rdsz, (int)sizeof(buf));
        retval = -1;
        goto hash_cleanup;
    }

    memcpy(hash, buf, hashlen);

hash_cleanup:
    pclose(fp);
hash_exit:
    return retval;
}

#ifdef __cplusplus
// }
#endif
#endif // _SW_UPD_PACKDEF_H