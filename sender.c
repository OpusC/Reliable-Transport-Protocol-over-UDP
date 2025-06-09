/***********************************************************************
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
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/file.h>

#include "log.h"
#include "stcp.h"
#include "tcp.h"
#include "wraparound.h"

#include <stdbool.h>

#define STCP_SUCCESS 1
#define STCP_ERROR -1

typedef struct {
    packet pkt;
    unsigned int seqno; // TODO: Do I need this field?
    int retransmitCount;
    long timeSentMs;

} sentPacket;

typedef struct {
    sentPacket *sentPackets; // buffer where everything will be stored
    unsigned int writeIndex; // point to the next empty slot in the buffer
    unsigned int readIndex; // point to the oldest unacknowledged packet
    unsigned int capacity; // maximum capacity of the ring buffer
    unsigned int sizeBytes; // the number of bytes currently stored in the buffer
    unsigned int size; // num of elements in the ring buffer
} ringbuffer;

typedef struct {

    /* YOUR CODE HERE */
    int fd;
    int state;
    ringbuffer *sentPackets; // network byte order
    unsigned int lastSentSeq; // host byte order
    unsigned int lastAck; // host byte order

} stcp_send_ctrl_blk;
/* ADD ANY EXTRA FUNCTIONS HERE */

static ringbuffer *rbInit() {
    ringbuffer *rb = malloc(sizeof(ringbuffer));

    if (rb == NULL) {
        printf("no space to malloc ring buffer struct\n");
        exit(EXIT_FAILURE);
    }

    /* capacity of buffer (that contains packets that may be up to STCP_MU bytes)
     * will be maximum window size / maximum transmission unit
     */
    rb->capacity = STCP_MAXWIN / STCP_MTU;

    rb->sentPackets = calloc(rb->capacity, sizeof(sentPacket));
    if (rb->sentPackets == NULL) {
        printf("no space to malloc ring buffer packet array\n");
        exit(EXIT_FAILURE);
    }

    rb->size = 0;
    rb->sizeBytes = 0;
    rb->writeIndex = 0;
    rb->readIndex = 0;

    return rb;
}

static stcp_send_ctrl_blk *cbInit(int fd) {
    stcp_send_ctrl_blk *cb = malloc(sizeof(stcp_send_ctrl_blk));
    if (cb == NULL) {
        perror("malloc failed in cbInit\n");
        exit(EXIT_FAILURE);
    }
    cb->fd = fd;
    cb->state = STCP_SENDER_CLOSED;
    cb->sentPackets = rbInit();
    return cb;
}

static void rbFree(ringbuffer *rb) {
    free(rb->sentPackets);
    free(rb);
}

static bool rbAdd(ringbuffer *rb, sentPacket spkt) {
    // check if we can write, check if wraparound is needed
    if (rb->size >= rb->capacity) return false;

    // write
    rb->sentPackets[rb->writeIndex] = spkt;

    rb->size++;
    rb->sizeBytes += spkt.pkt.len;
    rb->writeIndex = (rb->writeIndex + 1) % rb->capacity;

    return true;
}

// starting from the write pointer, free packets if they are less than ackNo
static void rbRemoveAck(ringbuffer *rb, unsigned int ackNo) {
    while (rb->size > 0) {
        unsigned int oldestSeqNo = rb->sentPackets[rb->readIndex].pkt.hdr->ackNo;

        if (greater32(ackNo, oldestSeqNo)) {
            return;
        }

        rb->sizeBytes -= rb->sentPackets[rb->readIndex].pkt.len;
        rb->size--;
        rb->readIndex = (rb->readIndex + 1) % rb->capacity;

    }
}

static bool packetChecksum(packet *p, int len) {
    unsigned short checksumField = p->hdr->checksum;
    p->hdr->checksum = 0;
    unsigned short actualChecksum = ipchecksum(p->hdr, p->len);

    if (checksumField == actualChecksum) {
        return true;
    } else {
        printf("expected chksm %hu actual checksum %hu\n", checksumField, actualChecksum);
        return false;
    }
}


static int freeCtrlBlk(stcp_send_ctrl_blk *cb) {
    if (!cb) {
        printf("Tried to free ctrl_blk when there is no ctrl_blk\n");
        return STCP_ERROR;
    }
    // TODO: update for buffers
    if (cb->sentPackets) rbFree(cb->sentPackets);
    close(cb->fd);
    free(cb);
    return STCP_SUCCESS;
}

// lastSentSeq is in network order bytes
// returns host order byte
static unsigned int nextSeq(unsigned int increment, unsigned int lastSentSeq) {
    unsigned int last = ntohl(lastSentSeq);
    return plus32(last, increment);
}

// receivedSeq is in host order bytes
// returns host order byte
static unsigned int nextAck(int len, unsigned int receivedSeq) {
    return plus32(receivedSeq, len);
}

/* Create the send packet struct
 */
static sentPacket spktInit(int flags, unsigned short rwnd, unsigned int seq, unsigned int ack, unsigned char *data, int len) {
    sentPacket spkt;

    if (data != NULL) {
        /* offset the data pointer by tcpheader, because createSegment later overwrites
        * this portion of the struct
        */
        memcpy(spkt.pkt.data + sizeof(tcpheader), data, len);
    }

    createSegment(&spkt.pkt, flags, rwnd, seq, ack, spkt.pkt.data, len);
    dump('s', spkt.pkt.hdr, spkt.pkt.len);

    // convert packet header to network byte order
    htonHdr(spkt.pkt.hdr);

    // write checksum
    spkt.pkt.hdr->checksum = ipchecksum(spkt.pkt.hdr, spkt.pkt.len);

    // add info for sentPacket struct
    spkt.seqno = seq;
    spkt.timeSentMs = now();
    spkt.retransmitCount = 0;

    return spkt;
}

static packet *bfrToPkt(unsigned char *buffer, int len) {
    packet *pkt = malloc(sizeof(packet));
    if (!pkt) {
        return NULL;
    }

    pkt->len = len;

    memcpy(pkt->data, buffer, len);
    pkt->hdr = (tcpheader *) pkt->data;

    return pkt;
};

// Packet header is in host byte order
static bool checkPktFlags(packet *pkt, int flags) {
    return (pkt->hdr->flags & flags) == flags;
}

// I'm not sure if I want this function to check the expected Ack No like this
// Packet header is in host byte order
static bool checkPktAck(packet *pkt, unsigned int expectedAckNo) {
    return pkt->hdr->ackNo == expectedAckNo;
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

    // TODO: loop to break the data into pieces and call preparepkt

    // create packet and send it
    // ADD 1 to first seq # after SYN

    unsigned int nSeq = nextSeq(1, stcp_CB->pktSent->hdr->seqNo);
    unsigned int nAck = nextAck(stcp_CB->pktRec->len, stcp_CB->pktRec->hdr->seqNo);
    packet *spkt = preparepkt(ACK, STCP_MTU, nSeq, nAck, data, length); 
    setStcbSentPkt(stcp_CB, spkt);
    send(stcp_CB->fd, spkt, spkt->len, 0);

    // wait for ack and check it

    unsigned char buffer[STCP_MTU];
    int len = readWithTimeout(stcp_CB->fd, buffer, STCP_MIN_TIMEOUT);

    if (len == STCP_READ_TIMED_OUT) {
        // TODO: Handle this case properly
        goto cleanupPacket;
    } else if (len == STCP_READ_PERMANENT_FAILURE) {
        goto cleanupPacket;
    }

    // Move received data to packet struct
    packet *rpkt = bfrToPkt(buffer, len);
    if (!packetChecksum(rpkt, len)) {
        goto cleanupPacket;
    }
    htonHdr(rpkt->hdr);

    // Check packet has ACK flag and correct seq no
    // TODO: check ackNo at some point
    if (checkPktAck(rpkt, nextAck(stcp_CB->pktSent->len,
                                        ntohl(stcp_CB->pktSent->hdr->seqNo))), checkPktFlags(rpkt, ACK)) {

    }
    // TODO: Handle this case properly... what is this case?
    if (!rpkt) {
        printf("checkpkt error\n");
        goto cleanupPacket;
    }

    setStcbSCBReceivedPkt(stcp_CB, rpkt);
    return STCP_SUCCESS;

cleanupPacket:
    free(spkt);
    return STCP_ERROR;
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

    // starting seq # = 0, not random
    srand(time(NULL));
    unsigned int rnd = (unsigned int) rand();
    stcp_send_ctrl_blk *cb = cbInit(fd);
    cb->sentPackets = rbInit();


    sentPacket spkt = spktInit(SYN, STCP_MAXWIN, rnd, 0, NULL, 0);

    cb->lastSentSeq = spkt.seqno;

    rbAdd(cb->sentPackets, p);

    send(fd, p, p->len, 0);

    cb->state = STCP_SENDER_SYN_SENT;

    // We sent the packet, now wait for the ACK
    unsigned char buffer[STCP_MTU];
    int len = readWithTimeout(fd, buffer, STCP_MIN_TIMEOUT);

    if (len == STCP_READ_TIMED_OUT) {
        // TODO: Handle this case
        goto cleanupBoth;
    } else if (len == STCP_READ_PERMANENT_FAILURE) {
        goto cleanupBoth;
    }

    stcpSCB->state = STCP_SENDER_ESTABLISHED;

    packet *rpkt = bfrToPkt(buffer, len);
    packetChecksum(rpkt, len);
    htonHdr(rpkt->hdr);

    if (!(checkPktFlags(rpkt, ACK) && checkPktAck(rpkt, p->hdr->seqNo + 1))) {

        // TODO: Handle this case better
        printf("checkPkt or pktFlag error\n");
        goto cleanupBoth;
    }

    setStcbSCBReceivedPkt(stcpSCB, rpkt);


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
    printf("STCP CLOSE\n");

    // send FIN packet without ACK flag
    cb->state = STCP_SENDER_CLOSING;
    unsigned int nSeq = nextSeq((unsigned int)(cb->pktSent->len - sizeof(tcpheader)), cb->pktSent->hdr->seqNo);
    packet *spkt = preparepkt(FIN, STCP_MTU, nSeq, 0, 0, 0); 
    setStcbSentPkt(cb, spkt);
    send(cb->fd, spkt, spkt->len, 0);

    // enter FIN WAIT state
    cb->state = STCP_SENDER_FIN_WAIT;

    // receive the FIN ACK packet
    unsigned char buffer[STCP_MTU];
    int len = readWithTimeout(cb->fd, buffer, STCP_INITIAL_TIMEOUT);

    if (len == STCP_READ_TIMED_OUT) {
        // TODO: Handle this case properly
        goto cleanupPacket;
    } else if (len == STCP_READ_PERMANENT_FAILURE) {
        goto cleanupPacket;
    }

    // Move received data to packet struct
    packet *rpkt = bfrToPkt(buffer, len);
    if (!packetChecksum(rpkt, len)) {
        goto cleanupPacket;
    }
    htonHdr(rpkt->hdr);

    // Check packet has ACK flag and correct seq no
    // TODO: check ackNo at some point
    if (!(checkPktFlags(rpkt, ACK) && checkPktAck(rpkt, nextAck(cb->pktSent->len,
                                        ntohl(cb->pktSent->hdr->seqNo) + 1)))) {
        // Flag is wrong or ack # is wrong...
    }

    // TODO: Handle this case properly... what is this case?
    if (!rpkt) {
        printf("checkpkt error\n");
        goto cleanupPacket;
    }

    setStcbSCBReceivedPkt(cb, rpkt);

    // Close state
    cb->state = STCP_SENDER_CLOSED;
    // free the control block
    freeCtrlBlk(cb);

    return STCP_SUCCESS;

cleanupPacket:
    printf("STCP_ERROR\n");
    free(rpkt);
    free(spkt);
    return STCP_ERROR;
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
        // TODO: Handle case when open fails
    }
    printf("SYN handshake complete\n");
    /* Start to send data in file via STCP to remote receiver. Chop up
     * the file into pieces as large as max packet size and transmit
     * those pieces.
     */
    while (1) {
        num_read_bytes = read(file, buffer, sizeof(buffer));

        /* Break when EOF is reached */
        printf("num_read_bytes %d\n", num_read_bytes);
        if (num_read_bytes <= 0)
            break;

        // TODO: decide if I like this control flow
        // when should I return STCP_ERROR? Should this path
        // send a reset?
        // how does the while loop break when we call stcp_send?
        // stcp_send already breaks down the buffer sent into it into
        // the correct size for packets being sent
        // how is this loop supposed to be broken
        if (stcp_send(cb, buffer, num_read_bytes) == STCP_ERROR) {
            /* YOUR CODE HERE */
        }
    }

    printf("while loop ended\n");

    /* Close the connection to remote receiver */
    if (stcp_close(cb) == STCP_ERROR) {
        /* YOUR CODE HERE */
    }

    return 0;
}
