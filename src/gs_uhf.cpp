/**
 * @file gs_uhf.cpp
 * @author Mit Bailey (mitbailey99@gmail.com)
 * @brief 
 * @version See Git tags for version information.
 * @date 2021.08.03
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <si446x.h>
#include "gpiodev/gpiodev.h"
#include "gs_uhf.hpp"
#include "meb_debug.hpp"
#include "sw_update_packdef.h"

void *gs_uhf_rx_thread(void *args)
{
    // TODO: As of right now, there is no way to detect if the UHF Radio crashes, which may require a re-init. In this event, global_data->uhf_ready should be set to false and the radio should be re-init'd. However, this feature doesn't exist in the middleware.
    // TODO: Possibly just assume any uhf_read failure is because of a crash UHF?
    dbprintlf(BLUE_FG "Entered RX Thread");
    global_data_t *global = (global_data_t *)args;

    while (global->network_data->thread_status > 0)
    {
        si446x_info_t si_info[1];
        si_info->part = 0;

        // Init UHF.
        if (!global->uhf_ready)
        {
            global->uhf_initd = gs_uhf_init();
            dbprintlf(RED_FG "Init status: %d", global->uhf_initd);
            if (global->uhf_initd != 1)
            {
                dbprintlf(RED_FG "UHF Radio initialization failure (%d).", global->uhf_initd);
                usleep(5 SEC);
                continue;
            }

            // TODO: COMMENT OUT FOR DEBUGGING PURPOSES ONLY
#ifndef UHF_NOT_CONNECTED_DEBUG
            dbprintlf(GREEN_FG "UHF IS NOW ARMED AND READY");
            dbprintlf(GREEN_FG "UHF IS NOW ARMED AND READY");
            dbprintlf(GREEN_FG "UHF IS NOW ARMED AND READY");
            global->uhf_ready = true;
#endif
        }
        si446x_getInfo(si_info);
        dbprintlf(BLUE_FG "Read part: 0x%x", si_info->part);
        if ((si_info->part & 0x4460) != 0x4460)
        {
            global->uhf_ready = false;
            usleep(5 SEC);
            dbprintlf(FATAL "Part number mismatch: 0x%x, retrying init", si_info->part);
            continue;
        }

        char buffer[GST_MAX_PACKET_SIZE];
        memset(buffer, 0x0, sizeof(buffer));

        // Enable pipe mode.
        // gs_uhf_enable_pipe();

        // TODO: COMMENT OUT FOR DEBUGGING PURPOSES ONLY
#ifndef UHF_NOT_CONNECTED_DEBUG
        si446x_en_pipe();
#endif

        int retval = gs_uhf_read(buffer, sizeof(buffer), UHF_RSSI, &global->uhf_ready);

        if (retval < 0)
        {
            dbprintlf(RED_FG "UHF read error %d.", retval);
            continue;
        }
        else if (retval == 0)
        {
            // Timed-out.
            continue;
        }
        else
        {
            dbprintlf(BLUE_BG "Received from UHF.");
        }

        dbprintlf(BLUE_FG "UHF receive payload has a cmd_output_t.mod value of: %d", ((cmd_output_t *)buffer)->mod);
        NetFrame *network_frame = new NetFrame((unsigned char *)buffer, sizeof(cmd_output_t), NetType::DATA, NetVertex::CLIENT);
        network_frame->sendFrame(global->network_data);
        delete network_frame;
    }

    dbprintlf(FATAL "gs_uhf_rx_thread exiting!");
    if (global->network_data->thread_status > 0)
    {
        global->network_data->thread_status = 0;
    }
    return nullptr;
}

void *gs_network_rx_thread(void *args)
{
    dbprintlf(GREEN_FG "GS NETWORK RX THREAD STARTING");

    global_data_t *global = (global_data_t *)args;
    NetDataClient *network_data = global->network_data;

    // Similar, if not identical, to the network functionality in ground_station.
    // Roof UHF is a network client to the GS Server, and so should be very similar in socketry to ground_station.

    while (network_data->recv_active && network_data->thread_status > 0)
    {
        if (!network_data->connection_ready)
        {
            usleep(5 SEC);
            continue;
        }

        int read_size = 0;

        while (read_size >= 0 && network_data->recv_active && network_data->thread_status > 0)
        {
            dbprintlf(BLUE_BG "Waiting to receive...");

            NetFrame *netframe = new NetFrame();
            read_size = netframe->recvFrame(network_data);

            dbprintlf("Read %d bytes.", read_size);

            if (read_size >= 0)
            {
                dbprintlf("Received the following NetFrame:");
                netframe->print();
                netframe->printNetstat();

                // Extract the payload into a buffer.
                int payload_size = netframe->getPayloadSize();
                unsigned char *payload = (unsigned char *)malloc(payload_size);
                if (payload == nullptr)
                {
                    dbprintlf(FATAL "Memory for payload failed to allocate, packet lost.");
                    continue;
                }

                if (netframe->retrievePayload(payload, payload_size) < 0)
                {
                    dbprintlf(RED_FG "Error retrieving data.");
                    if (payload != nullptr)
                    {
                        free(payload);
                        payload = nullptr;
                    }
                    continue;
                }

                switch (netframe->getType())
                {
                case NetType::SW_UPDATE:
                {
                    dbprintlf(BLUE_FG "Received an SW_UPDATE frame!");
                    sw_update_info_t *info = (sw_update_info_t *) payload;

                    for (int i = 0; i < netframe->getPayloadSize(); i++)
                    {
                        printf("%c", payload[i]);
                    }

                    if (info->stage)
                    {
                        dbprintlf("Staging for a software update.");

                        // | NetFrame Header |     P   A   Y   L   O   A   D    | NetFrame Footer
                        //                   |  sw_update_info_t  |  file data  |

                        int file_size = netframe->getPayloadSize() - sizeof(sw_update_info_t);
                        size_t bytes_written = 0;
                        dbprintlf(BLUE_FG "Filename: %s", info->filename);
                        FILE *fp = fopen(info->filename, "wb");
                        if (fp != NULL)
                        {
                            bytes_written = fwrite(payload + sizeof(sw_update_info_t), 1, file_size, fp);
                            fclose(fp);
                        }
                        else
                        {
                            dbprintlf(RED_FG "Failed to open file to log sw_update file data.");
                        }

                        if (bytes_written == file_size)
                        {
                            dbprintlf(GREEN_FG "Software update successfully staged.");
                            global->staged = 1;
                        }
                        else
                        {
                            dbprintlf(RED_FG "Software update staging failed.");
                        }
                    }
                    else if (info->begin)
                    {
                        if (!global->staged)
                        {
                            dbprintlf(RED_FG "Tried to begin an update without first staging a file to upload.");
                            break;
                        }
                        else if (global->sw_upd_in_progress)
                        {
                            dbprintlf(RED_FG "Update already in progress.");
                            break;
                        }

                        strcpy(global->filename, info->filename);

                        global->sw_upd_in_progress = 1;
                        pthread_t sw_upd_tid;
                        pthread_create(&sw_upd_tid, NULL, gs_sw_send_file_thread, global);
                    }
                }
                case NetType::UHF_CONFIG:
                {
                    dbprintlf(BLUE_FG "Received an UHF CONFIG frame!");
                    // TODO: Configure yourself.
                    break;
                }
                case NetType::DATA:
                {
                    dbprintlf(BLUE_FG "Received a DATA frame!");

                    if (global->uhf_ready)
                    {
                        si446x_info_t si_info[1];
                        si_info->part = 0;
                        si446x_getInfo(si_info);
                        if ((si_info->part & 0x4460) != 0x4460)
                        {
                            dbprintlf(RED_FG "UHF Radio not available");
                            if (payload != nullptr)
                            {
                                free(payload);
                                payload = nullptr;
                            }
                            continue;
                            // TODO: DO we let the client know this failed?
                        }

                        // Activate pipe mode.
                        si446x_en_pipe();

                        dbprintlf(BLUE_FG "Attempting to transmit %d bytes to SPACE-HAUC.", payload_size);
                        ssize_t retval = gs_uhf_write((char *)payload, payload_size, &global->uhf_ready);
                        dbprintlf(BLUE_FG "Transmitted with value: %d (note: this is not the number of bytes sent).", retval);
                    }
                    else
                    {
                        dbprintlf(RED_FG "Cannot send received data, UHF radio is not ready!");
                        cs_ack_t nack[1];
                        nack->ack = 0;
                        nack->code = NACK_NO_UHF;

                        NetFrame *nack_frame = new NetFrame((unsigned char *)nack, sizeof(nack), NetType::NACK, NetVertex::CLIENT);
                        nack_frame->sendFrame(network_data);
                        delete nack_frame;
                    }
                    break;
                }
                case NetType::ACK:
                {
                    dbprintlf(BLUE_FG "Received an ACK frame.");
                    break;
                }
                case NetType::NACK:
                {
                    dbprintlf(BLUE_FG "Received a NACK frame.");
                    break;
                }
                default:
                {
                    break;
                }
                }
                if (payload != nullptr)
                {
                    free(payload);
                    payload = nullptr;
                }
            }
            else
            {
                break;
            }

            delete netframe;
        }
        if (read_size == -404)
        {
            dbprintlf(RED_BG "Connection forcibly closed by the server.");
            strcpy(network_data->disconnect_reason, "SERVER-FORCED");
            network_data->connection_ready = false;
            continue;
        }
        else if (errno == EAGAIN)
        {
            dbprintlf(YELLOW_BG "Active connection timed-out (%d).", read_size);
            strcpy(network_data->disconnect_reason, "TIMED-OUT");
            network_data->connection_ready = false;
            continue;
        }
        erprintlf(errno);
    }

    network_data->recv_active = false;

    dbprintlf(FATAL "DANGER! NETWORK RECEIVE THREAD IS RETURNING!");
    if (global->network_data->thread_status > 0)
    {
        global->network_data->thread_status = 0;
    }
    return nullptr;
}

int gs_uhf_init(void)
{
    // (void) gst_error_str; // suppress unused warning

    // WARNING: This function will call exit() on failure.
    dbprintlf(RED_BG "WARNING: si446x_init() calls exit() on failure!");
    // TODO: COMMENT OUT FOR DEBUGGING PURPOSES ONLY
#ifndef UHF_NOT_CONNECTED_DEBUG
    si446x_init();
#endif

    dbprintlf(GREEN_FG "si446x_init() successful!");
    /*
     * chipRev: 0x22
     * partBuild: 0x0
     * id: 0x8600
     * customer: 0x0
     * romId: 0x6
     * revExternal: 0x6
     * revBranch: 0x0
     * revInternal: 0x2
     * patch: 0x0
     * func: 0x1
     */
    // TODO: COMMENT OUT FOR DEBUGGING PURPOSES ONLY
#ifndef UHF_NOT_CONNECTED_DEBUG
    si446x_info_t info[1];
    memset(info, 0x0, sizeof(si446x_info_t));
    si446x_getInfo(info);
    int cond = (info->part & 0x4460) == 0x4460;
    return cond ? 1 : 0;
#endif
#ifdef UHF_NOT_CONNECTED_DEBUG
    return 1;
#endif
}

ssize_t gs_uhf_read(char *buf, ssize_t buffer_size, int16_t *rssi, bool *gst_done)
{
    if (buffer_size < GST_MAX_PAYLOAD_SIZE)
    {
        dbprintlf("Payload size incorrect.");
        return GST_ERROR;
    }

    gst_frame_t frame[1];
    memset(frame, 0x0, sizeof(gst_frame_t));

    ssize_t retval = 0;
    while (((retval = si446x_read(frame, sizeof(gst_frame_t), rssi)) <= 0) && (!(*gst_done)))
        ;

    if (retval != sizeof(gst_frame_t))
    {
        dbprintlf(RED_FG "Read in %d bytes, not a valid packet", retval);
        return -GST_PACKET_INCOMPLETE;
    }

    if (frame->guid != GST_GUID)
    {
        dbprintlf(RED_FG "GUID 0x%04x", frame->guid);
        return -GST_GUID_ERROR;
    }
    else if (frame->crc != frame->crc1)
    {
        dbprintlf(RED_FG "0x%x != 0x%x", frame->crc, frame->crc1);
        return -GST_CRC_MISMATCH;
    }
    else if (frame->crc != internal_crc16(frame->payload, GST_MAX_PAYLOAD_SIZE))
    {
        dbprintlf(RED_FG "CRC %d", frame->crc);
        return -GST_CRC_ERROR;
    }
    else if (frame->termination != GST_TERMINATION)
    {
        dbprintlf(RED_FG "TERMINATION 0x%x", frame->termination);
    }

    memcpy(buf, frame->payload, GST_MAX_PAYLOAD_SIZE);

    return retval;
}

ssize_t gs_uhf_write(char *buf, ssize_t buffer_size, bool *gst_done)
{
    if (buffer_size < GST_MAX_PAYLOAD_SIZE)
    {
        dbprintlf(RED_FG "Payload size incorrect.");
        return -1;
    }

    gst_frame_t frame[1];
    memset(frame, 0x0, sizeof(gst_frame_t));

    frame->guid = GST_GUID;
    memcpy(frame->payload, buf, buffer_size);
    frame->crc = internal_crc16(frame->payload, GST_MAX_PAYLOAD_SIZE);
    frame->crc1 = frame->crc;
    frame->termination = GST_TERMINATION;

    ssize_t retval = 0;
    while (retval == 0)
    {
        gpioWrite(PIN_TR, GPIO_HIGH);
        usleep(100000); // 100 ms
        retval = si446x_write(frame, sizeof(gst_frame_t));
        usleep(10000);
        gpioWrite(PIN_TR, GPIO_LOW);
        usleep(100000); // 100 ms
        if (retval == 0)
        {
            dbprintlf(RED_FG "Sent zero bytes.");
        }
    }

    dbprintlf(BLUE_FG "Transmitted with value: %d (note: this is not the number of bytes sent).", retval);

    return retval;
}

// TODO: Set global-> values properly throughout this process.
// TODO: Transmit over the network the proper updates during the updater process.
#define DATA_SIZE_MAX 48
#define PACKET_SIZE 64
#define MAX_SEND_ATTEMPTS 15
#define HASH_SIZE 32
// TODO: Make this into a thread so that the rest of the program will continue running.
// NOTE: The RX thread copies all SW-related data into global_data->sw_output and sets the new_sw_data flag.
void *gs_sw_send_file_thread(void *args) 
// int sw_gs_send_file(const char directory[], const char filename[], bool *done_upld)
{
    global_data_t *global = (global_data_t *) args;
    if (!global->sw_upd_in_progress)
    {
        dbprintlf(RED_FG "global->sw_upd_in_progress == false");
        return NULL;
    }

    bool done_upld = false;

    sw_update_info_t info[1] = {0};

    if (global->filename == NULL)
    {
        dbprintlf("File name not supplied.");
        // return ERR_FN_NULL;
        global->sw_upd_in_progress = false;
        return NULL;
    }
    else if (strlen(global->filename) >= SW_UPD_FN_SIZE)
    {
        dbprintlf("File name is too long.");
        // return ERR_FN_SIZE;
        global->sw_upd_in_progress = false;
        return NULL;
    }

    // Reset the condition.
    // *done_upld = false;
    // global->sw_upd_in_progress = true;

    char directory_filename[64];
    snprintf(directory_filename, 64, "%s%s", global->directory, global->filename);
    FILE *bin_fp = fopen(directory_filename, "rb");

    if (bin_fp == NULL)
    {
        dbprintlf(RED_FG"Could not open %s in directory %s.", global->filename, global->directory);
        // return ERR_BIN_DNE;
        global->sw_upd_in_progress = false;
        return NULL;
    }

    // Find the size of the binary file.
    fseek(bin_fp, 0, SEEK_END);
    ssize_t file_size = ftell(bin_fp);
    fseek(bin_fp, 0, SEEK_SET);

    dbprintlf("File %s contains %ld bytes.", global->filename, file_size);

    dbprintlf("Starting Ground Station's send file executor...");

    // Variables.
    ssize_t sent_bytes = gs_sw_get_sent_bytes(global->filename);

    if (sent_bytes < 0)
    {
        dbprintlf(RED_FG"Fatal error retrieving bytes sent for file named %s.", global->filename);
        // return -1;
        global->sw_upd_in_progress = false;
        return NULL;
    }

    volatile int sent_packets = (sent_bytes / DATA_SIZE_MAX) + ((sent_bytes % DATA_SIZE_MAX) > 0);
    ssize_t fn_sz = strlen(global->filename) + 1;
    int send_attempts = 0;
    // int packet_number = 0;
    int max_packets = (file_size / DATA_SIZE_MAX) + ((file_size % DATA_SIZE_MAX) > 0);
    ssize_t retval = 0;

    // Our initial state is to begin by sending primers until we get a good reply.
    sw_upd_mode mode = primer;

    // Primers, headers, and buffers.
    char rd_buf[PACKET_SIZE];
    char wr_buf[PACKET_SIZE];

    // On the GS side, whether to send a primer or data packet will be determined initially by our current state: if we have just started into the method, send a S/R primer, if we are sending data packets and receiving good replies, continue to send DATA packets, if we receive a bad reply, determine what to do.

    dbprintlf("~ Entering FILE TRANSFER phase. ~");

    // Outer loop. Runs until we have sent the entire file.
    while ((mode != finish) && global->sw_upd_in_progress)
    {
        // Each loop we should set sent_bytes and sent_packets.
        sent_bytes = gs_sw_get_sent_bytes(global->filename);
        sent_packets = (sent_bytes / DATA_SIZE_MAX) + ((sent_bytes % DATA_SIZE_MAX) > 0);

        global->sw_upd_packet = sent_packets;

        // Update our update information struct with current data.
        info->current_packet = global->sw_upd_packet;
        info->total_packets = max_packets;
        info->in_progress = global->sw_upd_in_progress;
        info->finished = 0;

        // Send the info struct.
        NetFrame *update_netframe = new NetFrame((uint8_t *)info, sizeof(info), NetType::SW_UPDATE, NetVertex::CLIENT);
        update_netframe->sendFrame(global->network_data);
        delete update_netframe;

        dbprintlf(RED_FG"Sent_bytes: %d, sent_packets: %d", sent_bytes, sent_packets);

        ssize_t in_sz = 0;

        // Remember to clean your memory (and drink your ovaltine).
        memset(wr_buf, 0x0, PACKET_SIZE); // GS has this here instead of in the switch statement, unlike SH, because we write THEN read.

        switch (mode)
        {
        case primer:
        {
            // Map a S/R primer to the write buffer.
            sw_upd_startresume_t *sr_pmr = (sw_upd_startresume_t *)wr_buf;

            // Map a S/R reply header to the read buffer.
            sw_upd_startresume_reply_t *sr_rep = (sw_upd_startresume_reply_t *)rd_buf;

            // Set the START/RESUME primer's values.
            sr_pmr->cmd = SW_UPD_SRID;
            // memcpy(sr_pmr->filename, filename, fn_sz);
            strcpy(sr_pmr->filename, global->filename);
            sr_pmr->fid = 1;
            sr_pmr->sent_bytes = sent_bytes;
            sr_pmr->total_bytes = file_size;

            // Send the START/RESUME primer, and get back a reply.
            for (send_attempts = 0; (send_attempts < MAX_SEND_ATTEMPTS) && global->sw_upd_in_progress; send_attempts++)
            {
                dbprintlf("Attempting send of START/RESUME primer...");

                // Print S/R primer.
                // print_sr_pmr(sr_pmr);
                // memprintl_hex(wr_buf, PACKET_SIZE);
                // memprintl_char(wr_buf, PACKET_SIZE);

                // Send START/RESUME primer.
                // retval = gst_write(wr_buf, PACKET_SIZE);
                retval = gs_uhf_write(wr_buf, PACKET_SIZE, &done_upld);

                if (retval <= 0)
                {
                    dbprintlf(RED_FG"START/RESUME primer writing failed with value %d.", retval);
                    continue;
                }

                dbprintlf("Waiting for N/ACK...");

                // Wait for N/ACK.
                memset(rd_buf, 0x0, PACKET_SIZE);
                // retval = gst_read(rd_buf, PACKET_SIZE, NULL);
                retval = gs_uhf_read(rd_buf, PACKET_SIZE, UHF_RSSI, &done_upld);

                if (retval < 0)
                {
                    dbprintlf(YELLOW_FG"START/RESUME reply reading failed with value %d.", retval);

                    // Ask for a repeat.
                    // retval = gst_write(rept_cmd, sizeof(rept_cmd));
                    retval = gs_uhf_write(rept_cmd, sizeof(rept_cmd), &done_upld);

                    if (retval <= 0)
                    {
                        dbprintlf(RED_FG"REPT command writing failed with value %d.", retval);
                    }
                    else
                    {
                        dbprintlf("REPT command written successfully (%d).", retval);
                    }

                    continue;
                }
                else if (retval == 0)
                {
                    dbprintlf(RED_FG"START/RESUME reply reading timed out with value %d.", retval);
                    continue;
                }

#ifdef DEBUG_MODE_ACTIVE_GS

                if (fail_times_sr > 0)
                {
                    dbprintlf(YELLOW_FG"Flipping byte %d from 0x%02hhx to 0x%02hhx.", flip_byte_sr, rd_buf[flip_byte_sr], ~rd_buf[flip_byte_sr]);
                    rd_buf[flip_byte_sr] = ~rd_buf[flip_byte_sr];

                    fail_times_sr--;

                    dbprintlf(YELLOW_FG"Error induced. Press Enter to continue...");
                    getchar();
                }

#endif // DEBUG_MODE_ACTIVE_GS

                // Check if we read in a repeat command.
                if (!memcmp(rept_cmd, rd_buf, 5))
                { // We read in a REPT command, so, repeat last.
                    dbprintlf(YELLOW_FG"Repeat of previously sent transmission requested. Restarting previous send...");

#ifdef DEBUG_MODE_ACTIVE_GS
                    dbprintlf("Press enter to continue...");
                    getchar();
#endif // DEBUG_MODE_ACTIVE_GS

                    continue;
                }

                // Print the S/R reply.
                // print_sr_rep(sr_rep);
                // memprintl_hex(rd_buf, PACKET_SIZE);
                // memprintl_char(rd_buf, PACKET_SIZE);

                if (sr_rep->cmd != SW_UPD_SRID)
                {
                    dbprintlf(YELLOW_FG"The CMD value 0x%02x is invalid. Resending START/RESUME primer.", sr_rep->cmd);

#ifdef DEBUG_MODE_ACTIVE_GS
                    dbprintlf("Press enter to continue...");
                    getchar();
#endif // DEBUG_MODE_ACTIVE_GS

                    continue;
                }
                else if (memcmp((char *)sr_rep->filename, global->filename, fn_sz) != 0)
                {
                    dbprintlf(YELLOW_FG"The received filename (%s) does not match what was expected (%s). Resending START/RESUME primer.", sr_rep->filename, global->filename);

#ifdef DEBUG_MODE_ACTIVE_GS
                    dbprintlf("Press enter to continue...");
                    getchar();
#endif // DEBUG_MODE_ACTIVE_GS

                    continue;
                }
                else if (sr_rep->recv_bytes != sent_bytes)
                {
                    dbprintlf(YELLOW_FG"SPACE-HAUC and the Ground Station disagree on the number of bytes transfered (%d vs. %ld). Setting the Ground Station's value of sent bytes (local and file) and sent packets number to match SPACE-HAUC's and resending START/RESUME primer.", sr_rep->recv_bytes, sent_bytes);

                    // We should yield to SH here.

                    gs_sw_set_sent_bytes(global->filename, sr_rep->recv_bytes);
                    sent_bytes = sr_rep->recv_bytes;
                    sent_packets = (sent_bytes / DATA_SIZE_MAX) + ((sent_bytes % DATA_SIZE_MAX) > 0);

                    dbprintlf(YELLOW_FG"The Ground Station's values are now as follows: %d (local) %d (file).", sent_bytes, gs_sw_get_sent_bytes(global->filename));
                    dbprintlf(YELLOW_FG"Sent bytes (local / file): %d / %d", sent_bytes, gs_sw_get_sent_bytes(global->filename));
                    dbprintlf(YELLOW_FG"Sent packets: %d", sent_packets);

#ifdef DEBUG_MODE_ACTIVE_GS
                    dbprintlf("Press enter to continue...");
                    getchar();
#endif // DEBUG_MODE_ACTIVE_GS

                    // TODO: CONFIRM THIS WORKS.
                    // By iterating the values plus-one-packet, we are mutating SH's reply indicating its last received packet, into the next packet which we will send.
                    // dbprintlf(YELLOW_FG"Iterating our values plus-one-packet.");
                    // dbprintlf(YELLOW_FG"WARNING: THIS MAY CAUSE UNEXPECTED RESULTS IF TRANSMITTING THE FINAL PACKET.");

                    // sent_bytes += DATA_SIZE_MAX;
                    // gs_sw_set_sent_bytes(filename, sent_bytes);
                    // sent_packets++;

                    dbprintlf(YELLOW_FG"The Ground Station's values are now as follows: %d (local) %d (file).", sent_bytes, gs_sw_get_sent_bytes(global->filename));
                    dbprintlf(YELLOW_FG"Sent bytes (local / file): %d / %d", sent_bytes, gs_sw_get_sent_bytes(global->filename));
                    dbprintlf(YELLOW_FG"Sent packets: %d", sent_packets);

                    continue;
                }
                else if (sr_rep->total_packets != max_packets)
                {
                    dbprintlf(YELLOW_FG"SPACE-HAUC claims the file will consist of %d packets while the Ground Station claims it will be %d. Resending START/RESUME primer.", sr_rep->total_packets, max_packets);

#ifdef DEBUG_MODE_ACTIVE_GS
                    dbprintlf("Press enter to continue...");
                    getchar();
#endif // DEBUG_MODE_ACTIVE_GS

                    continue;
                }
                else
                {
                    dbprintlf("Received affirmative START/RESUME primer acknowledgement. Proceeding to data transfer beginning at packet %d.", sent_packets);
                    mode = data;
                    break;
                }
            }

            break; // case primer
        }

        case data:
        {
            // Map a DATA header to the write buffer.
            memset(wr_buf, 0x0, PACKET_SIZE);
            sw_upd_data_t *dt_hdr = (sw_upd_data_t *)wr_buf;

            // Map a DATA reply header onto the read buffer.
            sw_upd_data_reply_t *dt_rep = (sw_upd_data_reply_t *)rd_buf;

            // Make sure the number of the packet we are currently sending is correct.
            // packet_number = sent_packets;

            // Send the next DATA packet, and get a reply.
            for (send_attempts = 0; (send_attempts < MAX_SEND_ATTEMPTS) && global->sw_upd_in_progress; send_attempts++)
            {
                dbprintlf("Reading data from %s...", global->filename);

                // Read bytes from target file into buffer.
                fseek(bin_fp, sent_packets * DATA_SIZE_MAX, SEEK_SET);
                in_sz = fread(wr_buf + sizeof(sw_upd_data_t), 0x1, DATA_SIZE_MAX, bin_fp);

                if (in_sz <= 0)
                {
                    dbprintlf(RED_FG"Reached EOF when retrieving packet %d.", sent_packets);
                    break;
                }

                // Set the DATA header's values.
                dt_hdr->cmd = SW_UPD_DTID;
                dt_hdr->packet_number = sent_packets;
                dt_hdr->total_bytes = file_size;
                dt_hdr->data_size = in_sz;

                // Copy the DATA header into the write buffer.
                memcpy(wr_buf, dt_hdr, sizeof(sw_upd_data_t));

                dbprintlf("Attempting send of DATA header...");

                // Print the packet.
                // print_dt_hdr(dt_hdr);
                // memprintl_hex(wr_buf, PACKET_SIZE);
                // memprintl_char(wr_buf, PACKET_SIZE);

                // Send the DATA packet.
                // retval = gst_write(wr_buf, PACKET_SIZE);
                retval = gs_uhf_write(wr_buf, PACKET_SIZE, &done_upld);

                if (retval <= 0)
                {
                    dbprintlf(RED_FG"DATA packet writing failed with value %d.", retval);
                    continue;
                }

                dbprintlf("Waiting for N/ACK...");

                // Wait for a reply...
                memset(rd_buf, 0x0, PACKET_SIZE);
                // retval = gst_read(rd_buf, PACKET_SIZE, NULL);
                retval = gs_uhf_read(rd_buf, PACKET_SIZE, UHF_RSSI, &done_upld);

                if (retval < 0)
                {
                    dbprintlf(YELLOW_FG"DATA reply reading failed with value %d.", retval);

                    // Ask for a repeat.
                    // retval = gst_write(rept_cmd, sizeof(rept_cmd));
                    retval = gs_uhf_write(rept_cmd, sizeof(rept_cmd), &done_upld);

                    if (retval <= 0)
                    {
                        dbprintlf(RED_FG"REPT command writing failed with value %d.", retval);
                    }
                    else
                    {
                        dbprintlf("REPT command written successfully (%d).", retval);
                    }

                    continue;
                }
                else if (retval == 0)
                {
                    dbprintlf(RED_FG"DATA reply reading timed out with value %d.", retval);
                    continue;
                }

#ifdef DEBUG_MODE_ACTIVE_GS

                if (fail_times_dt > 0)
                {
                    dbprintlf(YELLOW_FG"Flipping byte %d from 0x%02hhx to 0x%02hhx.", flip_byte_dt, rd_buf[flip_byte_dt], ~rd_buf[flip_byte_dt]);
                    rd_buf[flip_byte_dt] = ~rd_buf[flip_byte_dt];

                    fail_times_dt--;

                    dbprintlf(YELLOW_FG"Error induced. Press Enter to continue...");
                    getchar();
                }

#endif // DEBUG_MODE_ACTIVE_GS

                // If we get here we no longer need the content in wr_buf.
                // memset(wr_buf, 0x0, PACKET_SIZE);

                // Check if we read in a repeat command.
                if (!memcmp(rept_cmd, rd_buf, 5))
                { // We read in a REPT command, so, repeat last.
                    dbprintlf(YELLOW_FG"Repeat of previously sent transmission requested. Restarting previous send...");

                    continue;
                }

                // Print the reply.
                // print_dt_rep(dt_rep);
                // memprintl_hex(rd_buf, PACKET_SIZE);
                // memprintl_char(rd_buf, PACKET_SIZE);

                if (dt_rep->cmd != SW_UPD_DTID)
                {
                    dbprintlf(YELLOW_FG"The CMD value 0x%02x is invalid. Resending DATA packet.", dt_rep->cmd);
                    continue;
                }
                else if (dt_rep->packet_number != sent_packets)
                {
                    dbprintlf(YELLOW_FG"SPACE-HAUC and the Ground Station disagree on the current packet number (%d vs. %d).", dt_rep->packet_number, sent_packets);

                    if (dt_rep->received != 1)
                    {
                        dbprintlf(YELLOW_FG"SPACE-HAUC's replied receive value is %d, indicating a bad receive. The packet it is requesting is number %d (max %d). Switching immediately to START/RESUME mode.", dt_rep->received, dt_rep->packet_number, max_packets);
                    }
                    else if (dt_rep->received == 1)
                    {
                        dbprintlf(RED_FG"SPACE-HAUC's replied receive value is %d, indicating a good receive, however the packet it is replying with (number %d) does not agree with the Ground Station (number %d). This may be fatal. Switching immediately to START/RESUME primer mode.", dt_rep->received, dt_rep->packet_number, sent_packets);
                    }

                    mode = primer;
                    break;
                }
                else if (dt_rep->total_packets != max_packets)
                {
                    dbprintlf(YELLOW_FG"SPACE-HAUC has calculated the file's maximum packet value to %d, as opposed to the Ground Station's %d. Resending DATA packet.", dt_rep->total_packets, max_packets);
                    continue;
                }
                else
                {
                    dbprintlf(RED_FG"Before: sent_bytes = %d, data_size = %d", sent_bytes, dt_hdr->data_size);
                    sent_bytes += dt_hdr->data_size;
                    gs_sw_set_sent_bytes(global->filename, sent_bytes);
                    dbprintlf(RED_FG"After: sent_bytes = %d, data_size = %d", sent_bytes, dt_hdr->data_size);
                    sent_packets++;

                    if (sent_bytes >= file_size)
                    {
                        dbprintlf("Received affirmative DATA acknowledgement. Successfully sent %ld/%ld bytes of %s.", sent_bytes, file_size, global->filename);
                        mode = transfer_complete;
                    }
                    else
                    {
                        dbprintlf("Received affirmative DATA acknowledgement. Proceeding to packet number %d.", sent_packets + 1);
                    }

                    break;
                }
            }
            break; // case data
        }

        case transfer_complete:
        {

            if (sent_bytes == file_size)
            {
                // Complete
                dbprintlf("File transfer complete with %ld/%ld bytes of %s having been successfully sent and confirmed per packet.", sent_bytes, file_size, global->filename);
            }
            else if (done_upld)
            {
                // Interrupted
                dbprintlf(YELLOW_FG"File transfer interrupted with %ld/%ld bytes of %s having been successfully sent and confirmed per packet.", sent_bytes, file_size, global->filename);
            }
            else if (sent_bytes <= 0)
            {
                // Error
                dbprintlf(RED_FG"An error has been encountered with %ld/%ld bytes of %s sent.", sent_bytes, file_size, global->filename);

                // return sent_bytes;
                global->sw_upd_in_progress = false;
                return NULL;
            }
            else
            {
                /// NOTE: Will reach this case if (recv_bytes != file_size).
                // ???
                dbprintlf(RED_FG"Confused.");

                // return ERR_CONFUSED;
                global->sw_upd_in_progress = false;
                return NULL;
            }

            mode = confirmation;

            break; // case transfer_complete
        }

        case confirmation:
        {

            dbprintlf("~ Entering FILE CONFIRMATION phase. ~");

            /// NOTE:: Send a CONF packet consisting of the original file's hash. Upon positive confirmation, SPACE-HAUC should unpack the sent data and place the final file at its destination. Upon negative confirmation, the entire file should be sent again.

            // Map a CONF header to the write buffer.
            sw_upd_conf_t *cf_hdr = (sw_upd_conf_t *)wr_buf;

            // Map a CONF reply to the read buffer.
            sw_upd_conf_reply_t *cf_rep = (sw_upd_conf_reply_t *)rd_buf;

            // Set CONF header values.
            cf_hdr->cmd = SW_UPD_CFID;
            cf_hdr->packet_number = sent_packets; // This and total should be equal.
            cf_hdr->total_packets = max_packets;

            checksum_md5(directory_filename, cf_hdr->hash, 32);

            dbprintlf("Sending CONF header...");

            // Print CONF header.
            // print_cf_hdr(cf_hdr);
            // memprintl_hex(wr_buf, PACKET_SIZE);
            // memprintl_char(wr_buf, PACKET_SIZE);

            // Send CONF header.
            // retval = gst_write(wr_buf, PACKET_SIZE);
            retval = gs_uhf_write(wr_buf, PACKET_SIZE, &done_upld);

            if (retval <= 0)
            {
                dbprintlf(RED_FG"CONF header writing failed with value %d.", retval);
                continue;
            }

            dbprintlf("Waiting for reply...");

            // Wait for reply.
            memset(rd_buf, 0x0, PACKET_SIZE);
            // retval = gst_read(rd_buf, PACKET_SIZE, NULL);
            retval = gs_uhf_read(rd_buf, PACKET_SIZE, UHF_RSSI, &done_upld);

            if (retval < 0)
            {
                dbprintlf(YELLOW_FG"CONF reply reading failed with value %d.", retval);

                // Ask for a repeat.
                // retval = gst_write(rept_cmd, sizeof(rept_cmd));
                retval = gs_uhf_write(rept_cmd, sizeof(rept_cmd), &done_upld);

                if (retval <= 0)
                {
                    dbprintlf(RED_FG"REPT command writing failed with value %d.", retval);
                }
                else
                {
                    dbprintlf("REPT command written successfully (%d).", retval);
                }

                continue;
            }
            else if (retval == 0)
            {
                dbprintlf(RED_FG"CONF reply reading timed out with value %d.", retval);
                continue;
            }

#ifdef DEBUG_MODE_ACTIVE_GS

            if (fail_times_cf > 0)
            {
                dbprintlf(YELLOW_FG"Flipping byte %d from 0x%02hhx to 0x%02hhx.", flip_byte_cf, rd_buf[flip_byte_cf], ~rd_buf[flip_byte_cf]);
                rd_buf[flip_byte_cf] = ~rd_buf[flip_byte_cf];

                fail_times_cf--;

                dbprintlf(YELLOW_FG"Error induced. Press Enter to continue...");
                getchar();
            }

#endif // DEBUG_MODE_ACTIVE_GS

            // Check if we read in a repeat command.
            if (!memcmp(rept_cmd, rd_buf, 5))
            { // We read in a REPT command, so, repeat last.
                dbprintlf(YELLOW_FG"Repeat of previously sent transmission requested. Restarting previous send...");

                continue;
            }

            // Print the CONF reply.
            // print_cf_rep(cf_rep);
            // memprintl_hex(rd_buf, PACKET_SIZE);
            // memprintl_char(rd_buf, PACKET_SIZE);

            /// NOTE: If cf_rep->request_packet is
            /// -2 : Bad receive. Send again.
            /// -1 : Good receive.
            /// >=0: Requesting packet.
            if (cf_rep->cmd != SW_UPD_CFID)
            {
                dbprintlf(YELLOW_FG"The CMD value 0x%02x is invalid. Resending CONF header.", cf_rep->cmd);
                break;
            }
            else if (cf_rep->total_packets != max_packets)
            {
                dbprintlf(YELLOW_FG"SPACE-HAUC has calculated the file's maximum packet value to %d, as opposed to the Ground Station's %d. Resending CONF header.", cf_rep->total_packets, max_packets);
                break;
            }
            else if (cf_rep->request_packet == REQ_PKT_RESEND)
            {
                dbprintlf(YELLOW_FG"SPACE-HAUC is requesting a re-send of the CONF header. Resending CONF header.");
                break;
            }
            else if (cf_rep->request_packet >= 0)
            {
                dbprintlf(YELLOW_FG"SPACE-HAUC is requesting a file re-send starting with packet %d.", cf_rep->request_packet);
                if (cf_rep->request_packet > max_packets)
                {
                    dbprintlf(RED_FG"SPACE-HAUC's file re-send request has been evaluated to be UNREASONABLE. Resending CONF header.");
                    break;
                }
                else if (cf_rep->request_packet <= max_packets)
                {
                    dbprintlf(YELLOW_FG"SPACE-HAUC's file re-send request has been evaluated to be REASONABLE. Sending a RESUME primer for packet %d.", cf_rep->request_packet);
                    sent_packets = cf_rep->request_packet;
                    sent_bytes = DATA_SIZE_MAX * sent_packets;
                    gs_sw_set_sent_bytes(global->filename, sent_bytes);
                    mode = primer;
                    break;
                }
            }
            else if (memcmp(cf_rep->hash, cf_hdr->hash, HASH_SIZE) != 0)
            {
                dbprintlf(YELLOW_FG"SPACE-HAUC has calculated a hash value for %s which differs from the Ground Station's.", global->filename);
                dbprintlf(YELLOW_FG"SPACE-HAUC: ");
                for (int i = 0; i < HASH_SIZE; i++)
                {
                    dbprintf(YELLOW_FG"%02x", *((unsigned char *)cf_rep->hash + i));
                }
                printf("\n");
                dbprintlf(YELLOW_FG"Ground Station: ");
                for (int i = 0; i < HASH_SIZE; i++)
                {
                    dbprintf(YELLOW_FG"%02x", *((unsigned char *)cf_hdr->hash + i));
                }
                printf("\n");
                dbprintlf(YELLOW_FG"Restarting file transfer.");
                sent_packets = 0;
                sent_bytes = 0;
                gs_sw_set_sent_bytes(global->filename, 0);
                mode = primer;
            }
            else
            {
                dbprintlf("Received affirmative file confirmation. Successfully confirmed %ld/%ld bytes of %s.", sent_bytes, file_size, global->filename);
                mode = finish;
            }

            break; // case confirmation
        }

        case finish:
        {
            dbprintlf(RED_FG"The Ground Station has finished the file transfer. You shouldn't be here. Confused.");
            break;
        }
        }
    }

    // Close the original binary file, which we read from initially.
    fclose(bin_fp);

    // return 1;
    global->sw_upd_in_progress = false;
    
    // Send a netframe notifying the GUI client of our finished status.
    info->in_progress = 0;
    info->finished = 1;

    NetFrame *update_netframe = new NetFrame((uint8_t *)info, sizeof(info), NetType::SW_UPDATE, NetVertex::CLIENT);
    update_netframe->sendFrame(global->network_data);
    delete update_netframe;

    return NULL;
}

ssize_t gs_sw_get_sent_bytes(const char filename[])
{
    // Read from {filename}.sent_bytes to see if this file was already mid-transfer and needs to continue at some specific point.
    char filename_bytes[128];
    snprintf(filename_bytes, 128, "%s.%s", filename, "gsbytes");

    int bytes_fp = -1;
    ssize_t sent_bytes = 0;

    if (access(filename_bytes, F_OK) == 0)
    {
        // File exists.
        bytes_fp = open(filename_bytes, O_RDONLY);
        if (bytes_fp < 3)
        {
            dbprintlf(RED_FG "%s exists but could not be opened.", filename_bytes);
            return ERR_FILE_OPEN;
        }
        lseek(bytes_fp, 0, SEEK_SET);
        if (read(bytes_fp, &sent_bytes, sizeof(ssize_t)) != sizeof(ssize_t))
        {
            dbprintlf(RED_FG "Error reading sent_bytes.");
        }
        dbprintlf(YELLOW_FG "%ld bytes of current transfer previously received by SH.", sent_bytes);
        close(bytes_fp);
    }
    else
    {
        // File does not exist.
        bytes_fp = open(filename_bytes, O_CREAT | O_EXCL, 0755);
        if (bytes_fp < 3)
        {
            dbprintlf(RED_FG "%s does not exist and could not be created.", filename_bytes);
            return ERR_FILE_OPEN;
        }
        lseek(bytes_fp, 0, SEEK_SET);
        int retval = write(bytes_fp, &sent_bytes, sizeof(ssize_t));
        if (retval != sizeof(ssize_t))
        {
            dbprintlf(RED_FG "Error %d", retval);
        }
        dbprintlf(YELLOW_FG "%s does not exist. Assuming transfer should start at packet 0.", filename_bytes);
        close(bytes_fp);
    }
    sync();
    return sent_bytes;
}

int gs_sw_set_sent_bytes(const char filename[], ssize_t sent_bytes)
{
    // Overwrite {filename}.bytes to contain {sent_bytes}.
    char filename_bytes[128];
    snprintf(filename_bytes, 128, "%s.%s", filename, "gsbytes");

    int bytes_fp = -1;
    bytes_fp = open(filename_bytes, O_RDWR | O_TRUNC);
    if (bytes_fp < 3)
    {
        dbprintlf(RED_FG "Could not open %s for overwriting.", filename_bytes);
        return ERR_FILE_OPEN;
    }
    lseek(bytes_fp, 0, SEEK_SET);
    if (write(bytes_fp, &sent_bytes, sizeof(ssize_t)) != sizeof(ssize_t))
    {
        dbprintlf(RED_FG "Could not write to %s", filename_bytes);
    }
    close(bytes_fp);

    sync();
    return 1;
}
