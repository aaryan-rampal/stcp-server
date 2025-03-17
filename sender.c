/************************************************************************
 * Adapted from a course at Boston University for use in CPSC 317 at UBC
 *
 *
 * The interfaces for the STCP sender (you get to implement them), and a
 * simple application-level routine to drive the sender.
 *
 * This routine reads the data to be transferred over the connection
 * from a file specified and invokes the STCP send functionality to
 * deliver the packets as an ordered sequence of datagrams.
 *
 * Version 2.0
 *
 *
 *************************************************************************/

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "stcp.h"

#define STCP_SUCCESS 1
#define STCP_ERROR -1

#define TCP_HEADER_SIZE sizeof(tcpheader)

typedef struct {
    // seqNo is in host endianness
    uint32_t seqNo;  // Sequence number of the packet
    // pkt is in network endianness
    packet pkt;               // Copy of the packet sent
    int retransmissionCount;  // Count of retransmissions
} OutstandingPacket;

typedef struct {
    /* YOUR CODE HERE */
    unsigned short windowSize;  // window size
    uint32_t isn;               // initial sequence number

    uint32_t nextSeqNo;
    uint32_t maxSeqNo;  // ensure all seqNo packets sent are <= maxSeqNo

    // TODO: maybe dont need first one
    uint32_t lastRecvdSeqNo;  // last received sequence number
    uint32_t lastRecvdAckNo;  // last ack number seen

    OutstandingPacket outstanding[STCP_MAXWIN];
    int outstandingCount;

    int duplicateAckCount;

    int state;
    int fd;
} stcp_send_ctrl_blk;

/* ADD ANY EXTRA FUNCTIONS HERE */

#define CHECKSUM_FAILED -2
#define PACKET_TIMEOUT -3
#define SOCKET_FAILURE -4

const char SENT = 's';

void setIpChecksum(packet *pkt) {
    pkt->hdr->checksum = 0;
    pkt->hdr->checksum = ipchecksum((void *)pkt, pkt->len);
}

// Log the current contents of the outstanding packet array.
void logOutstandingPackets(stcp_send_ctrl_blk *cb) {
    logLog("init",
           "Outstanding Packet Array (count: %d):", cb->outstandingCount);
    for (int i = 0; i < cb->outstandingCount; i++) {
        logLog("init", "  Index %d: seqNo = %u, retransmissionCount = %d", i,
               cb->outstanding[i].seqNo,
               cb->outstanding[i].retransmissionCount);
    }
}

/**
 * Create a packet with the given flags and data.
 * This function initializes the packet header, sets sequence/ack numbers,
 * and calculates the checksum.
 */
void createPacket(stcp_send_ctrl_blk *cb, packet *pkt, int flags,
                  unsigned char *data, int len) {
    pkt->len = TCP_HEADER_SIZE + len;
    createSegment(pkt, flags, cb->windowSize, cb->nextSeqNo, cb->lastRecvdSeqNo,
                  data, len);
}

// gets called with network endianness
void addOutstandingPacket(stcp_send_ctrl_blk *cb, packet *pkt) {
    cb->outstanding[cb->outstandingCount].seqNo = ntohl(pkt->hdr->seqNo);
    cb->outstanding[cb->outstandingCount].pkt = *pkt;  // store a copy
    cb->outstanding[cb->outstandingCount].retransmissionCount = 0;
    cb->outstandingCount++;
    logOutstandingPackets(cb);  // log after addition
}

void removeOutstandingPackets(stcp_send_ctrl_blk *cb, uint32_t ackNo) {
    int newCount = 0;
    for (int i = 0; i < cb->outstandingCount; i++) {
        if (cb->outstanding[i].seqNo >= ackNo) {
            // Keep this packet.
            cb->outstanding[newCount++] = cb->outstanding[i];
        }
    }
    cb->outstandingCount = newCount;
    logOutstandingPackets(cb);  // log after deletion
}

/**
 * Send a packet over the network using the provided file descriptor.
 * Logs errors if the send operation fails.
 */
int sendPacket(int fd, packet *pkt, stcp_send_ctrl_blk *cb) {
    dump(SENT, pkt, pkt->len);  // Log packet details

    // Convert to network byte order and compute checksum
    htonHdr(pkt->hdr);
    setIpChecksum(pkt);

    int res = send(fd, pkt, pkt->len, 0);
    if (res < 0) {
        logPerror("send");
        return -1;
    }
    cb->nextSeqNo += payloadSize(pkt) + getSyn(pkt->hdr) + getFin(pkt->hdr);
    // calling this function with network endianness
    addOutstandingPacket(cb, pkt);
    return res;
}

int retransmitPacket(stcp_send_ctrl_blk *cb, uint32_t seqNo) {
    for (int i = 0; i < cb->outstandingCount; i++) {
        if (cb->outstanding[i].seqNo == seqNo) {
            packet pkt_copy = cb->outstanding[i].pkt;
            dump(SENT, &pkt_copy, pkt_copy.len);
            int res = send(cb->fd, &pkt_copy, pkt_copy.len, 0);
            if (res < 0) {
                logPerror("Retransmit send");
                return -1;
            }
            cb->outstanding[i].retransmissionCount++;
            return res;
        }
    }
    return -1;
}

int receiveAndValidatePacket(int fd, packet *pkt, int timeout,
                             stcp_send_ctrl_blk *cb) {
    int res;
    int packetReceived = 1;
    while (packetReceived) {
        res = readWithTimeout(fd, (unsigned char *)pkt, timeout);
        logLog("init", "Read result: %d", res);

        switch (res) {
            case STCP_READ_PERMANENT_FAILURE:
                logPerror("Permanaent failure with socket");
                return SOCKET_FAILURE;
            case STCP_READ_TIMED_OUT:
                logLog("init", "Request timed out");
                if (cb->outstandingCount > 0) {
                    uint32_t oldestSeq = cb->outstanding[0].seqNo;
                    retransmitPacket(cb, oldestSeq);
                }
                timeout = min(STCP_MAX_TIMEOUT, timeout * 2);
                continue;
            default:
                packetReceived = 0;
                break;
        }
    }

    logLog("init", "Packet received");
    unsigned short oldChecksum = pkt->hdr->checksum;
    pkt->hdr->checksum = 0;
    logLog("init", "Packet length: %d", pkt->hdr->checksum);
    unsigned short computedChecksum = ipchecksum((void *)pkt, pkt->len);
    if (computedChecksum != oldChecksum) {
        logPerror("Packet checksum error");
        logLog("init",
               "Computed checksum is %04x, but received checksum is %04x",
               computedChecksum, pkt->hdr->checksum);
        return CHECKSUM_FAILED;
    }

    logLog("init", "Checksums match");
    ntohHdr(pkt->hdr);

    // TODO: maybe check if ack is in order
    cb->windowSize = pkt->hdr->windowSize;
    cb->lastRecvdSeqNo =
        pkt->hdr->seqNo + (getSyn(pkt->hdr) || getFin(pkt->hdr) ? 1 : 0);
    cb->lastRecvdAckNo = max(cb->lastRecvdAckNo, pkt->hdr->ackNo);
    removeOutstandingPackets(cb, pkt->hdr->ackNo);

    return STCP_SUCCESS;
}

/*
 * Send STCP. This routine is to send all the data (len bytes).  If more
 * than MSS bytes are to be sent, the routine breaks the data into multiple
 * packets. It will keep sending data until the send window is full or all
 * the data has been sent. At which point it reads data from the network to,
 * hopefully, get the ACKs that open the window. You will need to be careful
 * about timing your packets and dealing with the last piece of data.
 *
 * Your sender program will spend almost all of its time in either this
 * function or in tcp_close().  All input processing (you can use the
 * function readWithTimeout() defined in stcp.c to receive segments) is done
 * as a side effect of the work of this function (and stcp_close()).
 *
 * The function returns STCP_SUCCESS on success, or STCP_ERROR on error.
 */
int stcp_send(stcp_send_ctrl_blk *stcp_CB, unsigned char *data, int length) {
    /* YOUR CODE HERE */
    if (!stcp_CB || !data || length <= 0) {
        logPerror("Invalid arguments");
        return STCP_ERROR;
    }

    unsigned char *left = data;
    unsigned char *right = data + length;

    // still have data to send
    while (left < right) {
        // keep sending until we hit window
        logLog("init", "Sending data");
        while (stcp_CB->windowSize > 0 && left < right) {
            int bytesRemaining = right - left;
            int chunkSize = min(STCP_MSS, right - left);
            logLog("init", "Inner loop: left=%p, right=%p, bytesRemaining=%d",
                   left, right, bytesRemaining);
            logLog("init",
                   "Calculated chunkSize=%d (STCP_MSS=%d), remainingWindow=%d",
                   chunkSize, STCP_MSS, stcp_CB->windowSize);
            if (chunkSize > stcp_CB->windowSize) break;

            packet pkt;
            createPacket(stcp_CB, &pkt, ACK, left, chunkSize);
            memcpy(pkt.data + TCP_HEADER_SIZE, left, chunkSize);
            sendPacket(stcp_CB->fd, &pkt, stcp_CB);

            left += chunkSize;
            stcp_CB->windowSize -= chunkSize;
            logLog("init", "After sending: left=%p, remainingWindow=%d", left,
                   stcp_CB->windowSize);
        }

        // wait for ACKs
        while (stcp_CB->windowSize <= length) {
            logLog("init", "Window is full, waiting for ACKs");
            packet ackPacket;
            int res = receiveAndValidatePacket(stcp_CB->fd, &ackPacket,
                                               STCP_INITIAL_TIMEOUT, stcp_CB);
            if (res < 0) {
                return -1;
            }
            logLog("init", "got here?");

            // update window size and last acknowledged sequence number
            stcp_CB->windowSize = ackPacket.hdr->windowSize;
            stcp_CB->lastRecvdAckNo = ackPacket.hdr->ackNo;
        }
    }

    return STCP_SUCCESS;
}

int finishAllAcks(stcp_send_ctrl_blk *stcp_CB) {
    // all data sent, waiting for final ACK
    while (stcp_CB->lastRecvdAckNo < stcp_CB->nextSeqNo) {
        logLog("init",
               "Waiting for final ACK, lastAckNo = %u, lastSentSeq = %u",
               stcp_CB->lastRecvdAckNo, stcp_CB->nextSeqNo);

        packet ackPacket;
        initPacket(&ackPacket, ackPacket.data, TCP_HEADER_SIZE);
        int res = receiveAndValidatePacket(stcp_CB->fd, &ackPacket,
                                           STCP_INITIAL_TIMEOUT, stcp_CB);
        logLog("init", "res = %d", res);
        if (res < 0) {
            return STCP_ERROR;
        }
        logLog("init", "got here?");

        stcp_CB->lastRecvdAckNo = ackPacket.hdr->ackNo;
        logLog("init", "lastRecvdAckNo = %u", stcp_CB->lastRecvdAckNo);
    }
    logLog("init", "All ACKs received");
    return STCP_SUCCESS;
}

/*
 * Open the sender side of the STCP connection. Returns the pointer to
 * a newly allocated control block containing the basic information
 * about the connection. Returns NULL if an error happened.
 *
 * If you use udp_open() it will use connect() on the UDP socket
 * then all packets then sent and received on the given file
 * descriptor go to and are received from the specified host. Reads
 * and writes are still completed in a datagram unit size, but the
 * application does not have to do the multiplexing and
 * demultiplexing. This greatly simplifies things but restricts the
 * number of "connections" to the number of file descriptors and isn't
 * very good for a pure request response protocol like DNS where there
 * is no long term relationship between the client and server.
 */
stcp_send_ctrl_blk *stcp_open(char *destination, int sendersPort,
                              int receiversPort) {
    logLog("init", "Sending from port %d to <%s, %d>", sendersPort, destination,
           receiversPort);
    // Since I am the sender, the destination and receiversPort name the other
    // side
    int fd = udp_open(destination, receiversPort, sendersPort);
    (void)fd;
    /* YOUR CODE HERE */
    if (fd < 0) {
        logPerror("udp_open");
        return NULL;
    }
    logLog("init", "No errors in udp_open");

    // creating control block
    stcp_send_ctrl_blk *cb =
        (stcp_send_ctrl_blk *)malloc(sizeof(stcp_send_ctrl_blk));
    if (cb == NULL) {
        logPerror("malloc cb");
        goto cleanup_socket;
    }
    logLog("init", "No errors in malloc cb");

    // setting initial values
    cb->fd = fd;
    cb->lastRecvdAckNo = 0;
    cb->lastRecvdSeqNo = 0;
    cb->isn = rand() % (UINT16_MAX - 1);
    cb->nextSeqNo = cb->isn;
    cb->windowSize = STCP_MAXWIN;
    cb->state = STCP_SENDER_SYN_SENT;

    // creating SYN packet
    packet synPacket;
    // TODO: 0 or 1 byte for size
    createPacket(cb, &synPacket, SYN, NULL, 0);
    sendPacket(fd, &synPacket, cb);

    // waiting for SYN-ACK
    packet synAckPacket;
    initPacket(&synAckPacket, synAckPacket.data, TCP_HEADER_SIZE);

    int res =
        receiveAndValidatePacket(fd, &synAckPacket, STCP_INITIAL_TIMEOUT, cb);
    if (res < 0) {
        goto cleanup_cb;
    }

    // response was not SYN-ACK
    if (!(getSyn(synAckPacket.hdr) && getAck(synAckPacket.hdr))) {
        logPerror("not SYN-ACK error");
        logLog("init", "SYN and ACK have the values %d and %d",
               getSyn(synAckPacket.hdr), getAck(synAckPacket.hdr));
        goto cleanup_cb;
    }
    logLog("init", "packet has SYN and ACK flags");

    // send response ACK
    packet ackPacket;
    createPacket(cb, &ackPacket, ACK, NULL, 0);
    sendPacket(fd, &ackPacket, cb);
    cb->state = STCP_SENDER_ESTABLISHED;

    // waiting for ACK
    packet lastAckPacket;
    initPacket(&lastAckPacket, lastAckPacket.data, TCP_HEADER_SIZE);
    res =
        receiveAndValidatePacket(fd, &lastAckPacket, STCP_INITIAL_TIMEOUT, cb);
    if (res < 0) {
        goto cleanup_cb;
    }

    // response was not ACK
    if (!(getAck(lastAckPacket.hdr))) {
        logPerror("not ACK error");
        logLog("init", "ACK is %d", getAck(lastAckPacket.hdr));
        goto cleanup_cb;
    }
    logLog("init", "packet has ACK flag");

    logLog("init", "ended syn ack process");
    cb->outstandingCount = 0;
    return cb;

cleanup_cb:
    free(cb);
cleanup_socket:
    close(fd);
    return NULL;
}

/*
 * Make sure all the outstanding data has been transmitted and
 * acknowledged, and then initiate closing the connection. This
 * function is also responsible for freeing and closing all necessary
 * structures that were not previously freed, including the control
 * block itself.
 *
 * Returns STCP_SUCCESS on success or STCP_ERROR on error.
 */
int stcp_close(stcp_send_ctrl_blk *cb) {
    cb->state = STCP_SENDER_CLOSING;

    // Step 1: Ensure all outstanding data has been acknowledged
    while (cb->lastRecvdAckNo < cb->nextSeqNo) {
        logLog("close", "Waiting for outstanding data to be ACKed...");
        packet tempPacket;
        initPacket(&tempPacket, tempPacket.data, TCP_HEADER_SIZE);
        int res = receiveAndValidatePacket(cb->fd, &tempPacket,
                                           STCP_INITIAL_TIMEOUT, cb);

        if (res < 0) {
            logPerror("Timeout/error while waiting for outstanding ACKs");
            goto cleanup_cb;
        }
    }

    // creating FIN packet
    packet finPacket;
    // TODO: 0 or 1 byte for size
    createPacket(cb, &finPacket, FIN, NULL, 1);
    sendPacket(cb->fd, &finPacket, cb);

    // Step 2: Move to FIN_WAIT state
    cb->state = STCP_SENDER_FIN_WAIT;

    // waiting for ACK
    packet ackPacket;
    initPacket(&ackPacket, ackPacket.data, TCP_HEADER_SIZE);
    int res =
        receiveAndValidatePacket(cb->fd, &ackPacket, STCP_INITIAL_TIMEOUT, cb);
    if (res < 0) {
        goto cleanup_cb;
    }

    // response was not ACK
    if (!getAck(ackPacket.hdr)) {
        logPerror("not ACK error");
        logLog("init", "ACK have the values %d", getAck(ackPacket.hdr));
        goto cleanup_cb;
    }
    logLog("init", "packet has ACK flag");

    // close the connection
    cb->state = STCP_SENDER_CLOSED;
    close(cb->fd);
    free(cb);
    return STCP_SUCCESS;

cleanup_cb:
    free(cb);
cleanup_socket:
    close(cb->fd);
    return -1;
}
/*
 * Return a port number based on the uid of the caller.  This will
 * with reasonably high probability return a port number different from
 * that chosen for other uses on the undergraduate Linux systems.
 *
 * This port is used if ports are not specified on the command line.
 */
int getDefaultPort() {
    uid_t uid = getuid();
    int port = (uid % (32768 - 512) * 2) + 1024;
    assert(port >= 1024 && port <= 65535 - 1);
    return port;
}

/*
 * This application is to invoke the send-side functionality.
 */
int main(int argc, char **argv) {
    stcp_send_ctrl_blk *cb;

    char *destinationHost;
    int receiversPort, sendersPort;
    char *filename = NULL;
    int file;
    /* You might want to change the size of this buffer to test how your
     * code deals with different packet sizes.
     */
    // TODO
    unsigned char buffer[STCP_MSS];
    int num_read_bytes;

    logConfig("sender", "init,segment,error,failure,packet");
    /* Verify that the arguments are right */
    if (argc > 5 || argc == 1) {
        fprintf(stderr,
                "usage: sender DestinationIPAddress/Name receiveDataOnPort "
                "sendDataToPort filename\n");
        fprintf(stderr, "or   : sender filename\n");
        exit(1);
    }
    if (argc == 2) {
        filename = argv[1];
        argc--;
    }

    // Extract the arguments
    destinationHost = argc > 1 ? argv[1] : "localhost";
    receiversPort = argc > 2 ? atoi(argv[2]) : getDefaultPort();
    sendersPort = argc > 3 ? atoi(argv[3]) : getDefaultPort() + 1;
    if (argc > 4) filename = argv[4];

    /* Open file for transfer */
    file = open(filename, O_RDONLY);
    if (file < 0) {
        logPerror(filename);
        exit(1);
    }

    /*
     * Open connection to destination.  If stcp_open succeeds the
     * control block should be correctly initialized.
     */
    cb = stcp_open(destinationHost, sendersPort, receiversPort);
    if (cb == NULL) {
        /* YOUR CODE HERE */
        logPerror("sctp_open");
        exit(1);
    }

    /* Start to send data in file via STCP to remote receiver. Chop up
     * the file into pieces as large as max packet size and transmit
     * those pieces.
     */
    while (1) {
        num_read_bytes = read(file, buffer, sizeof(buffer));

        /* Break when EOF is reached */
        printf("num_read_bytes: %d\n", num_read_bytes);
        if (num_read_bytes <= 0) {
            finishAllAcks(cb);
            break;
        }

        if (stcp_send(cb, buffer, num_read_bytes) == STCP_ERROR) {
            /* YOUR CODE HERE */
            free(cb);
            close(file);
            exit(1);
        }
    }
    printf("broke out\n");

    /* Close the connection to remote receiver */
    if (stcp_close(cb) == STCP_ERROR) {
        /* YOUR CODE HERE */
    }

    return 0;
}
