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

typedef struct {
    /* YOUR CODE HERE */
    unsigned short windowSize;  // window size
    uint32_t isn;               // initial sequence number
    uint32_t nextSeqNo;
    uint32_t maxSeqNo;  // ensure all seqNo packets sent are <= maxSeqNo
    uint32_t lastAckNo;
    struct packet *packetsAwaitingAck;
    int state;
} stcp_send_ctrl_blk;
/* ADD ANY EXTRA FUNCTIONS HERE */
void logPacket(packet *pkt, char *packetType, int convert) {
    if (convert) ntohHdr(pkt->hdr);
    logLog("init", "%s %s payload %d bytes", packetType,
           tcpHdrToString(pkt->hdr), payloadSize(pkt));
    if (convert) htonHdr(pkt->hdr);
}

void setIpChecksum(packet *pkt) {
    pkt->hdr->checksum = 0;
    pkt->hdr->checksum = ipchecksum((void *)pkt, pkt->len);
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
        return NULL;
    }
    logLog("init", "No errors in malloc cb");

    // setting initial values
    cb->lastAckNo = rand() % (UINT32_MAX - 1);
    cb->isn = rand() % (UINT32_MAX - 1);
    cb->nextSeqNo = cb->isn;
    cb->windowSize = STCP_MAXWIN;
    cb->state = STCP_SENDER_SYN_SENT;

    // creating SYN packet
    packet synPacket;
    synPacket.len = sizeof(tcpheader);
    createSegment(&synPacket, SYN, cb->windowSize, cb->nextSeqNo, cb->lastAckNo,
                  NULL, 0);
    setSyn(synPacket.hdr);
    htonHdr(synPacket.hdr);
    setIpChecksum(&synPacket);

    // sending SYN packet
    // TODO: GPT said third param is 0, but third param should be flags, so
    // shouldn't it be SYN?
    send(fd, &synPacket, synPacket.len, 0);
    logPacket(&synPacket, "s", 1);

    // waiting for SYN-ACK
    packet synAckPacket;
    initPacket(&synAckPacket, synAckPacket.data, sizeof(tcpheader));
    logPacket(&synAckPacket, "r", 1);
    synAckPacket.hdr->checksum = 0;
    int res = readWithTimeout(fd, (unsigned char *)&synAckPacket,
                              STCP_INITIAL_TIMEOUT);
    logPacket(&synAckPacket, "r", 1);

    switch (res) {
        case STCP_READ_PERMANENT_FAILURE:
            logPerror("permanennt failure with socket");
            free(cb);
            return NULL;
            break;
        case STCP_READ_TIMED_OUT:
            logLog("init", "Timed out waiting for SYN-ACK");
            free(cb);
            return NULL;
            break;
        default:
            break;
    }

    // check checksum to see if they match
    unsigned short computedChecksum =
        ipchecksum((void *)&synAckPacket, synAckPacket.len);
    if (computedChecksum != synAckPacket.hdr->checksum) {
        logPerror("synAckPacket checksum error");
        logLog("init",
               "Computed checksum is %04x, but received checksum is %04x",
               computedChecksum, synAckPacket.hdr->checksum);
        free(cb);
        return NULL;
    }

    ntohHdr(synAckPacket.hdr);
    // response was not SYN-ACK
    if (!(getSyn(synAckPacket.hdr) && getAck(synAckPacket.hdr))) {
        logPerror("not SYN-ACK error");
        logLog("init", "SYN and ACK have the values %d and %d",
               getSyn(synAckPacket.hdr), getAck(synAckPacket.hdr));
        free(cb);
        return NULL;
    }
    logLog("init", "Checksums match");

    // TODO: not checking for checksum right now
    // update window size from response
    cb->windowSize = synAckPacket.hdr->windowSize;
    // update sequence numbers
    cb->lastAckNo = synAckPacket.hdr->seqNo;
    // TODO: deal with this case
    if (cb->nextSeqNo > synAckPacket.hdr->ackNo) {
        logLog("init", "Received SYN-ACK with ackNo %d, but nextSeqNo is %d",
               synAckPacket.hdr->ackNo, cb->nextSeqNo);
        cb->nextSeqNo = synAckPacket.hdr->ackNo;
    }

    // send response ACK
    packet ackPacket;
    initPacket(&ackPacket, NULL, sizeof(tcpheader));
    createSegment(&ackPacket, ACK, cb->windowSize, cb->nextSeqNo, cb->lastAckNo,
                  NULL, 0);
    send(fd, &ackPacket, ackPacket.len, 0);

    cb->state = STCP_SENDER_ESTABLISHED;
    return cb;
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
    /* YOUR CODE HERE */
    return STCP_SUCCESS;
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

    logConfig("sender", "init,segment,error,failure");
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
    }

    /* Start to send data in file via STCP to remote receiver. Chop up
     * the file into pieces as large as max packet size and transmit
     * those pieces.
     */
    while (1) {
        num_read_bytes = read(file, buffer, sizeof(buffer));

        /* Break when EOF is reached */
        if (num_read_bytes <= 0) break;

        if (stcp_send(cb, buffer, num_read_bytes) == STCP_ERROR) {
            /* YOUR CODE HERE */
        }
    }

    /* Close the connection to remote receiver */
    if (stcp_close(cb) == STCP_ERROR) {
        /* YOUR CODE HERE */
    }

    return 0;
}
