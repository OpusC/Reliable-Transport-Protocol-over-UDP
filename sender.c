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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/file.h>

#include "stcp.h"
#include "tcp.h"

// hopefully we use c99 or greater
#include <stdbool.h>

#define STCP_SUCCESS 1
#define STCP_ERROR -1

typedef struct {

    /* YOUR CODE HERE */
    packet *lastPacketSent;
    int fd;
    int state;

} stcp_send_ctrl_blk;
/* ADD ANY EXTRA FUNCTIONS HERE */
static bool packetChecksum(packet *p, int len) {
    printf("packetChecksum\n");
    unsigned short checksumField = p->hdr->checksum;
    printf("accessed checksum\n");
    p->hdr->checksum = 0;
    unsigned short actualChecksum = ipchecksum(p->hdr, p->len);
    printf("called upchecksum\n");

    if (checksumField == actualChecksum) {
        return true;
    } else {
        return false;
    }
}


static void bfrToPkt(unsigned char *buffer, packet *pkt, int len) {
    memcpy(pkt->data, buffer + sizeof(tcpheader), len - sizeof(tcpheader));
};

static packet *checkpkt(unsigned char *buffer, int len, int expectedFlags, unsigned int expectedAckno) {
    packet *rpkt = malloc(sizeof(packet));
    if (!rpkt) {
        return NULL;
    }
    rpkt->len = len;
    rpkt->hdr = (tcpheader *) buffer;
    htonHdr(rpkt->hdr);

    if ((rpkt->hdr->flags & expectedFlags) != expectedFlags) {
        printf("receiver did not send ack packet back\n");
        // TODO: send reset?
        goto cleanupPacket;
    }

    if (rpkt->hdr->ackNo != expectedAckno) {
        printf("expected sequence number %u but got %u\n", expectedAckno, rpkt->hdr->ackNo);
        goto cleanupPacket;
    }

    bfrToPkt(buffer, rpkt, len);

    return rpkt;

cleanupPacket:
    free(rpkt);
    return NULL;
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
int stcp_send(stcp_send_ctrl_blk *stcp_CB, unsigned char* data, int length) {

    /* YOUR CODE HERE */
    // For now, do NOT break data into multiple packets. Send one packet
    // then close the connection

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
stcp_send_ctrl_blk * stcp_open(char *destination, int sendersPort,
                             int receiversPort) {
    logLog("init", "Sending from port %d to <%s, %d>", sendersPort, destination, receiversPort);
    // Since I am the sender, the destination and receiversPort name the other side
    int fd = udp_open(destination, receiversPort, sendersPort);
    /*
     * what does this do? I think this means ignore the fd?
     * actually it is here to suppress compiler warnings about unused
     * variables apparently
     */
    (void) fd;

    /* YOUR CODE HERE */

    packet *p = malloc(sizeof(packet));
    if (p == NULL) {
        // This function returns NULL if an error has occured
        return NULL;
    }
    // starting seq # = 0, not random

    // len should be sizeof(tcpheader), because the initial SYN packet
    // only contains the header and no data
    createSegment(p, SYN, STCP_MSS, 0, 0, NULL, 0);

    // prepare the data to be in network order
    htonHdr(p->hdr);

    p->hdr->checksum = ipchecksum(p->hdr, p->len);

    dump('s', p->hdr, p->len);
    // return control block with useful information
    stcp_send_ctrl_blk *stcpSCB = malloc(sizeof(stcp_send_ctrl_blk));

    if (stcpSCB == NULL) {
        goto cleanupPacket;
    }

    stcpSCB->lastPacketSent = p;
    stcpSCB->fd = fd;


    // idk if we need to worry about little and big endian...
    // can encapsulate this into a sendpkt(int fd, void *pkt, int len)
    // function that dumps, calls htoNdr and adds checksum
    send(fd, p, p->len, 0);

    stcpSCB->state = STCP_SENDER_SYN_SENT;

    // We sent the packet, not wait for the ACK
    unsigned char buffer[STCP_MTU];
    // this function already calls ntoHdr
    int len = readWithTimeout(fd, buffer, STCP_MIN_TIMEOUT);

    if (len == STCP_READ_TIMED_OUT) {
        // TODO: Handle this case
        goto cleanupBoth;
    } else if (len == STCP_READ_PERMANENT_FAILURE) {
        goto cleanupBoth;
    }

    stcpSCB->state = STCP_SENDER_ESTABLISHED;

    // Should this also do the memcpy, checksum?
    packet *rpkt = checkpkt(buffer, len, ACK, p->hdr->seqNo + 1);
    if (!rpkt) {
        printf("checkpkt error\n");
        goto cleanupBoth;
    }



    stcpSCB->state = STCP_SENDER_ESTABLISHED;
    packetChecksum(rpkt, len);

    return stcpSCB;

cleanupBoth:
    free(stcpSCB);
cleanupPacket:
    free(p);
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
    unsigned char buffer[STCP_MSS];
    int num_read_bytes;

    // ADD packet to the logging
    logConfig("sender", "init,segment,error,failure,packet");
    /* Verify that the arguments are right */
    if (argc > 5 || argc == 1) {
        fprintf(stderr, "usage: sender DestinationIPAddress/Name receiveDataOnPort sendDataToPort filename\n");
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
        if (num_read_bytes <= 0)
            break;

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
