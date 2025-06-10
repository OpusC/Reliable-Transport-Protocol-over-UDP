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
    int timeout;
    long timeSentMs;

} sentPacket;

typedef struct {
    sentPacket *sentPackets; // buffer where everything will be stored
    unsigned int writeIndex; // point to the next empty slot in the buffer
    unsigned int readIndex; // point to the oldest unacknowledged packet
    unsigned int capacity; // maximum capacity of the ring buffer
    unsigned short sizeBytes; // the number of bytes currently stored in the buffer
    unsigned int size; // num of elements in the ring buffer
} ringbuffer;

typedef struct {

    /* YOUR CODE HERE */
    int fd;
    int state;
    ringbuffer *rb; // ring buffer for sent packets
    unsigned int nextSeq; // last seqno sent, host byte order
    unsigned int lastSeq; // last received seqno, host byte order
    unsigned int nextAck; // next ack to send, host byte order
    int lastLen; // length of last packet
    unsigned int lastAck; // last ack received, host byte order
    unsigned short rwnd; // most recent receive window size

} stcp_send_ctrl_blk;
/* ADD ANY EXTRA FUNCTIONS HERE */

/*
 * send a packet, updating the timeSentMs field
 */
void sendPacket(int fd, sentPacket *spkt) {
    spkt->timeSentMs = now();
    printf("\033[32mPacket length is %d\033[0m\n", spkt->pkt.len);
    int val = send(fd, &spkt->pkt, spkt->pkt.len, 0);

    if (val == EMSGSIZE || val == -1) {
        printf("Error writing to socket in stcp_open\n");
        exit(EXIT_FAILURE);
    }
}

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
    cb->rb = rbInit();
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

    int sizeIncrease = (unsigned short) (spkt.pkt.len - sizeof(tcpheader));

    printf("\033[32mAdding %hu to sending window size\033[0m\n", sizeIncrease);
    rb->sizeBytes += sizeIncrease;
    rb->writeIndex = (rb->writeIndex + 1) % rb->capacity;

    return true;
}

// starting from the read index, increment read index until we reach an
// unacknowledged packet
static void removeAckdPkts(ringbuffer *rb, unsigned int ackNo) {
    while (rb->size > 0) {
        sentPacket spkt = rb->sentPackets[rb->readIndex];// .pkt.hdr->seqNo;
        unsigned int oldestSeqNo = spkt.seqno;

        if (!greater32(ackNo, oldestSeqNo)) {
            return;
        }

        int sizeIncrease = (unsigned short) (spkt.pkt.len - sizeof(tcpheader));
        printf("\033[32mRemoving %hu from sending window size\033[0m\n", sizeIncrease);
        rb->sizeBytes -= sizeIncrease;
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
    if (cb->rb) rbFree(cb->rb);
    close(cb->fd);
    free(cb);
    return STCP_SUCCESS;
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

    spkt.seqno = seq;
    printf("spktInit seqNo %u\n", spkt.seqno);

    // convert packet header to network byte order
    htonHdr(spkt.pkt.hdr);

    // write checksum
    spkt.pkt.hdr->checksum = ipchecksum(spkt.pkt.hdr, spkt.pkt.len);

    // add info for sentPacket struct
    spkt.timeSentMs = now();
    spkt.timeout = STCP_MIN_TIMEOUT;

    return spkt;
}

// copies from given buffer to a packet pointer
static packet *bfrToPkt(packet *pkt, unsigned char *buffer, int len) {
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
    // divide up data into chunks, up to STCP_MTU + last remainder.
    // when total_size == rwnd, begin transmission

    while (length > 0) {

        // prepare all packets, add to ring buffer
        while (stcp_CB->rb->sizeBytes <= stcp_CB->rwnd) {
            unsigned short receiveWindowLeft = stcp_CB->rwnd - stcp_CB->rb->sizeBytes;
            unsigned short packetSize = min(min(STCP_MSS, length), receiveWindowLeft);
            if (packetSize == 0) break;
            sentPacket spkt = spktInit(ACK, STCP_MAXWIN, stcp_CB->nextSeq, stcp_CB->nextAck, data, packetSize);

            rbAdd(stcp_CB->rb, spkt);

            data += packetSize; // increment pointer to next portion of data
            length -= packetSize; // keep track of remaining length
            stcp_CB->nextSeq = plus32(packetSize, stcp_CB->nextSeq);
            if (length <= 0) break;

            if (receiveWindowLeft == 0) break;
        }

        unsigned int idx = 0;
        while (greater32(stcp_CB->rb->size, idx)) {
            // loop through ring buffer, sending all packets
            printf("sending packet\n");
            sentPacket spkt = stcp_CB->rb->sentPackets[(stcp_CB->rb->readIndex + idx) % stcp_CB->rb->capacity];
            sendPacket(stcp_CB->fd, &spkt);
            idx++;
        }

        printf("\033[31mReceive window size %hu sending window size %hu\033[0m\n",stcp_CB->rwnd ,stcp_CB->rb->sizeBytes);

        // Reading packets loop
        int len;
        int timeout = STCP_MIN_TIMEOUT;
        unsigned int greatestAck = stcp_CB->lastAck;
        while ((now() - stcp_CB->rb->sentPackets[stcp_CB->rb->readIndex].timeSentMs) < timeout) {
            packet p;
            unsigned char bfr[STCP_MTU];

            // read pkt
            // TODO: Fast Retransmission
            len = readWithTimeout(stcp_CB->fd, bfr, 5);

            if (len == STCP_READ_TIMED_OUT) {
                continue; // this timeout doesn't mean anything, only the while loop
                // exiting will mean something
            } else if (len == STCP_READ_PERMANENT_FAILURE) {
                printf("socket permanent failure\n");
                exit(EXIT_FAILURE);
            } else {
                // parse pkt
                bfrToPkt(&p, bfr, len);

                // checksum
                if (!packetChecksum(&p, len)) continue; // checksum doesn't match; discard packet

                // convert to host byte order
                ntohHdr(p.hdr);

                // check flags
                if (!checkPktFlags(&p, ACK)) continue;

                // rbRemoveAck
                if (greater32(p.hdr->ackNo, greatestAck)) greatestAck = p.hdr->ackNo;

                removeAckdPkts(stcp_CB->rb, greatestAck);
                stcp_CB->nextAck = p.hdr->seqNo + 1; // TODO: update to cumulative ack
                // do this by... updating the last ack
                stcp_CB->lastAck = p.hdr->ackNo;
                printf("received seqno %u\n", p.hdr->seqNo);
                stcp_CB->lastSeq = ntohl(p.hdr->seqNo);

                unsigned short rwnd = p.hdr->windowSize;
                if (rwnd != stcp_CB->rwnd) {
                    printf("\033[mUpdating receive window size to %hu\033[m\n", rwnd);
                    stcp_CB->rwnd = rwnd;
                } 
            }

        }


    }

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
    srand(time(NULL));
    unsigned int rnd = (unsigned int) rand();
    stcp_send_ctrl_blk *cb = cbInit(fd);
    cb->rb = rbInit();


    sentPacket spkt = spktInit(SYN, STCP_MAXWIN, rnd, 0, NULL, 0);

    cb->nextSeq = plus32(1, spkt.seqno);

    // receiving temp buffer
    unsigned char buffer[STCP_MTU];

    cb->state = STCP_SENDER_SYN_SENT;

    int len;
    int timeout = STCP_MIN_TIMEOUT;

    while (true) {

        sendPacket(fd, &spkt);

        // receive
        len = readWithTimeout(fd, buffer, timeout);

        if (len == STCP_READ_TIMED_OUT) {
            timeout = stcpNextTimeout(timeout);
            continue;
        } else if (len == STCP_READ_PERMANENT_FAILURE) {
            printf("socket permanent failure\n");
            exit(EXIT_FAILURE);
        } else {
            // check checksum and flags
            // TODO: change this to 
            packet rpkt;
            bfrToPkt(&rpkt, buffer, len);
            packetChecksum(&rpkt, len);
            ntohHdr(rpkt.hdr);
            if (!(checkPktFlags(&rpkt, SYN | ACK) && checkPktAck(&rpkt, spkt.seqno + 1))) {
                continue; // ignore packet
            } else {
                cb->lastAck = rpkt.hdr->ackNo;
                cb->nextAck = rpkt.hdr->seqNo + 1;
                cb->rwnd = rpkt.hdr->windowSize;
                removeAckdPkts(cb->rb, rpkt.hdr->ackNo);
                return cb;
            }
        }
    }
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

    printf("last sent seqno %u\n", cb->nextSeq);

    sentPacket spkt = spktInit(FIN, STCP_MAXWIN, cb->nextSeq, cb->nextSeq, NULL, 0);

    int len;
    int timeout = STCP_MIN_TIMEOUT;

    unsigned char buffer[STCP_MTU];

    while (true) {
        sendPacket(cb->fd, &spkt);

        len = readWithTimeout(cb->fd, buffer, timeout);

        if (len == STCP_READ_TIMED_OUT) {
            timeout = stcpNextTimeout(timeout);
            printf("timeout %d\n", timeout);
            if (timeout >= STCP_MAX_TIMEOUT) break;

            continue;
        } else if (len == STCP_READ_PERMANENT_FAILURE) {
            printf("socket permanent failure in stcp_close\n");
            exit(EXIT_FAILURE);
        } else {
            packet rpkt;
            bfrToPkt(&rpkt, buffer, len);
            packetChecksum(&rpkt, len);
            ntohHdr(rpkt.hdr);

            if (!checkPktFlags(&rpkt, FIN | ACK) &&
                checkPktAck(&rpkt, spkt.seqno + 1)) {
                continue; // ignore packet
            } else {
                break;
            }

        }

    }

    freeCtrlBlk(cb);
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
    // TODO: change this to be larger
    unsigned char buffer[STCP_MAXWIN];
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
        printf("ctrl_blk returned from stcb_open() was NULL\n");
        exit(EXIT_FAILURE);
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
