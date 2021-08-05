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
#include "gs_uhf.hpp"
#include "meb_debug.hpp"

// SegFault
// is gs_uhf_rx_thread

void *gs_uhf_rx_thread(void *args)
{
    // TODO: As of right now, there is no way to detect if the UHF Radio crashes, which may require a re-init. In this event, global_data->uhf_ready should be set to false and the radio should be re-init'd. However, this feature doesn't exist in the middleware.
    // TODO: Possibly just assume any uhf_read failure is because of a crash UHF?

    global_data_t *global_data = (global_data_t *)args;

    while (global_data->thread_status > 0)
    {
        // Init UHF.
        if (!global_data->uhf_ready)
        {
            global_data->modem = uhf_init(RADIO_DEVICE_NAME);
            if (global_data->modem < 0)
            {
                dbprintlf(RED_FG "UHF Radio initialization failure (%d).", global_data->modem);
                usleep(5 SEC);
                continue;
            }
            global_data->uhf_ready = true;
        }

        char buffer[UHF_MAX_PAYLOAD_SIZE];
        memset(buffer, 0x0, sizeof(buffer));

        int retval = uhf_read(global_data->modem, buffer, sizeof(buffer));

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
            dbprintlf("Received from UHF.");
        }

        gs_network_transmit(global_data->network_data, CS_TYPE_DATA, CS_ENDPOINT_CLIENT, buffer, sizeof(buffer));
    }

    if (global_data->thread_status > 0)
    {
        global_data->thread_status = 0;
    }
    return nullptr;
}

void *gs_network_rx_thread(void *args)
{
    global_data_t *global_data = (global_data_t *)args;
    network_data_t *network_data = global_data->network_data;

    // TODO: Similar, if not identical, to the network functionality in ground_station.
    // Roof UHF is a network client to the GS Server, and so should be very similar in socketry to ground_station.

    while (network_data->rx_active)
    {
        if (!network_data->connection_ready)
        {
            usleep(5 SEC);
            continue;
        }

        int read_size = 0;

        while (read_size >= 0 && network_data->rx_active)
        {
            char buffer[sizeof(NetworkFrame) * 2];
            memset(buffer, 0x0, sizeof(buffer));

            dbprintlf(BLUE_BG "Waiting to receive...");
            read_size = recv(network_data->socket, buffer, sizeof(buffer), 0);
            dbprintlf("Read %d bytes.", read_size);

            if (read_size > 0)
            {
                dbprintf("RECEIVED (hex): ");
                for (int i = 0; i < read_size; i++)
                {
                    printf("%02x", buffer[i]);
                }
                printf("(END)\n");

                // Parse the data by mapping it to a NetworkFrame.
                NetworkFrame *network_frame = (NetworkFrame *)buffer;

                // Check if we've received data in the form of a NetworkFrame.
                if (network_frame->checkIntegrity() < 0)
                {
                    dbprintlf("Integrity check failed (%d).", network_frame->checkIntegrity());
                    continue;
                }
                dbprintlf("Integrity check successful.");

                global_data->netstat = network_frame->getNetstat();

                // For now, just print the Netstat.
                uint8_t netstat = network_frame->getNetstat();
                dbprintlf(BLUE_FG "NETWORK STATUS");
                dbprintf("GUI Client ----- ");
                ((netstat & 0x80) == 0x80) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
                dbprintf("Roof UHF ------- ");
                ((netstat & 0x40) == 0x40) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
                dbprintf("Roof X-Band ---- ");
                ((netstat & 0x20) == 0x20) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");
                dbprintf("Haystack ------- ");
                ((netstat & 0x10) == 0x10) ? printf(GREEN_FG "ONLINE" RESET_ALL "\n") : printf(RED_FG "OFFLINE" RESET_ALL "\n");

                // Extract the payload into a buffer.
                int payload_size = network_frame->getPayloadSize();
                unsigned char *payload = (unsigned char *)malloc(payload_size);
                if (network_frame->retrievePayload(payload, payload_size) < 0)
                {
                    dbprintlf(RED_FG "Error retrieving data.");
                    continue;
                }

                NETWORK_FRAME_TYPE type = network_frame->getType();
                switch (type)
                {
                case CS_TYPE_ACK:
                {
                    dbprintlf(BLUE_FG "Received an ACK frame!");
                    break;
                }
                case CS_TYPE_NACK:
                {
                    dbprintlf(BLUE_FG "Received a NACK frame!");
                    break;
                }
                case CS_TYPE_CONFIG_UHF:
                {
                    dbprintlf(BLUE_FG "Received an UHF CONFIG frame!");
                    // TODO: Configure yourself.
                    break;
                }
                case CS_TYPE_DATA:
                {
                    dbprintlf(BLUE_FG "Received a DATA frame!");
                    // TODO: Send to SPACE-HAUC.
                    if (global_data->uhf_ready)
                    {
                        ssize_t retval = uhf_write(global_data->modem, (char *)payload, payload_size);
                        dbprintlf("Transmitted %d bytes to SPACE-HAUC.");
                    }
                    else
                    {
                        dbprintlf(RED_FG "Cannot send received data, UHF radio is not ready!");
                    }
                    break;
                }
                case CS_TYPE_CONFIG_XBAND:
                case CS_TYPE_NULL:
                case CS_TYPE_ERROR:
                default:
                {
                    break;
                }
                }
                free(payload);
            }
            else
            {
                break;
            }
        }
        if (read_size == 0)
        {
            dbprintlf(RED_BG "Connection forcibly closed by the server.");
            strcpy(network_data->discon_reason, "SERVER-FORCED");
            network_data->connection_ready = false;
            continue;
        }
        else if (errno == EAGAIN)
        {
            dbprintlf(YELLOW_BG "Active connection timed-out (%d).", read_size);
            strcpy(network_data->discon_reason, "TIMED-OUT");
            network_data->connection_ready = false;
            continue;
        }
        erprintlf(errno);
    }

    network_data->rx_active = false;
    dbprintlf(FATAL "DANGER! NETWORK RECEIVE THREAD IS RETURNING!");

    if (global_data->thread_status > 0)
    {
        global_data->thread_status = 0;
    }
    return nullptr;
}

void *gs_polling_thread(void *args)
{
    dbprintlf(BLUE_FG "Beginning polling thread.");

    global_data_t *global_data = (global_data_t *)args;
    network_data_t *network_data = global_data->network_data;

    while (network_data->rx_active)
    {
        if (network_data->connection_ready)
        {
            NetworkFrame *null_frame = new NetworkFrame(CS_TYPE_NULL, 0x0);
            null_frame->storePayload(CS_ENDPOINT_SERVER, NULL, 0);
            null_frame->sendFrame(network_data);
            delete null_frame;
        }
        else
        {
            // Get our GS Network connection back up and running.
            gs_connect_to_server(global_data);
        }
        usleep(SERVER_POLL_RATE SEC);
    }

    dbprintlf(FATAL "GS_POLLING_THREAD IS EXITING!");
    if (global_data->thread_status > 0)
    {
        global_data->thread_status = 0;
    }
    return nullptr;
}

int gs_network_transmit(network_data_t *network_data, NETWORK_FRAME_TYPE type, NETWORK_FRAME_ENDPOINT endpoint, void *data, int data_size)
{
    if (data_size < 0)
    {
        printf("Error: data_size is %d.\n", data_size);
        printf("Cancelling transmit.\n");
        return -1;
    }

    // Create a NetworkFrame to send our data in.
    NetworkFrame *clientserver_frame = new NetworkFrame(type, data_size);
    clientserver_frame->storePayload(endpoint, data, data_size);

    clientserver_frame->sendFrame(network_data);

    return 1;
}

int gs_connect_to_server(global_data_t *global_data)
{
    network_data_t *network_data = global_data->network_data;
    int connect_status = -1;

    dbprintlf(BLUE_FG "Attempting connection to %s:%d.", SERVER_IP, SERVER_PORT);

    network_data->serv_ip->sin_port = htons(SERVER_PORT);
    if ((network_data->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        dbprintlf(RED_FG "Socket creation error.");
        connect_status = -1;
    }
    else if (inet_pton(AF_INET, SERVER_IP, &network_data->serv_ip->sin_addr) <= 0)
    {
        dbprintlf(RED_FG "Invalid address; address not supported.");
        connect_status = -2;
    }
    else if (gs_connect(network_data->socket, (struct sockaddr *)network_data->serv_ip, sizeof(network_data->serv_ip), 1) < 0)
    {
        dbprintlf(RED_FG "Connection failure.");
        connect_status = -3;
    }
    else
    {
        // If the socket is closed, but recv(...) was already called, it will be stuck trying to receive forever from a socket that is no longer active. One way to fix this is to close the RX thread and restart it. Alternatively, we could implement a recv(...) timeout, ensuring a fresh socket value is used.
        // Here, we implement a recv(...) timeout.
        struct timeval timeout;
        timeout.tv_sec = RECV_TIMEOUT;
        timeout.tv_usec = 0;
        setsockopt(network_data->socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);

        network_data->connection_ready = true;
        connect_status = 1;
    }

    return connect_status;
}

int gs_connect(int socket, const struct sockaddr *address, socklen_t socket_size, int tout_s)
{
    int res;
    long arg;
    fd_set myset;
    struct timeval tv;
    int valopt;
    socklen_t lon;

    // Set non-blocking.
    if ((arg = fcntl(socket, F_GETFL, NULL)) < 0)
    {
        dbprintlf(RED_FG "Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    arg |= O_NONBLOCK;
    if (fcntl(socket, F_SETFL, arg) < 0)
    {
        dbprintlf(RED_FG "Error fcntl(..., F_SETFL)");
        erprintlf(errno);
        return -1;
    }

    // Trying to connect with timeout.
    res = connect(socket, address, socket_size);
    if (res < 0)
    {
        if (errno == EINPROGRESS)
        {
            dbprintlf(YELLOW_FG "EINPROGRESS in connect() - selecting");
            do
            {
                if (tout_s > 0)
                {
                    tv.tv_sec = tout_s;
                }
                else
                {
                    tv.tv_sec = 1; // Minimum 1 second.
                }
                tv.tv_usec = 0;
                FD_ZERO(&myset);
                FD_SET(socket, &myset);
                res = select(socket + 1, NULL, &myset, NULL, &tv);
                if (res < 0 && errno != EINTR)
                {
                    dbprintlf(RED_FG "Error connecting.");
                    erprintlf(errno);
                    return -1;
                }
                else if (res > 0)
                {
                    // Socket selected for write.
                    lon = sizeof(int);
                    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon) < 0)
                    {
                        dbprintlf(RED_FG "Error in getsockopt()");
                        erprintlf(errno);
                        return -1;
                    }

                    // Check the value returned...
                    if (valopt)
                    {
                        dbprintlf(RED_FG "Error in delayed connection()");
                        erprintlf(valopt);
                        return -1;
                    }
                    break;
                }
                else
                {
                    dbprintlf(RED_FG "Timeout in select(), cancelling!");
                    return -1;
                }
            } while (1);
        }
        else
        {
            fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
            dbprintlf(RED_FG "Error connecting.");
            erprintlf(errno);
            return -1;
        }
    }
    // Set to blocking mode again...
    if ((arg = fcntl(socket, F_GETFL, NULL)) < 0)
    {
        dbprintlf("Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    arg &= (~O_NONBLOCK);
    if (fcntl(socket, F_SETFL, arg) < 0)
    {
        dbprintlf("Error fcntl(..., F_GETFL)");
        erprintlf(errno);
        return -1;
    }
    return socket;
}