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
    
    int val = send(fd, &spkt->pkt.data, spkt->pkt.len, 0);
    printf("sent a packet\n");

    if (val == EMSGSIZE || val == -1) {
        printf("Error writing to socket in stcp_open\n");
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
    cb->rwnd = STCP_MAXWIN; // use max window size for the default window size
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

    printf("rbAdd: storing packet with length %d\n", rb->sentPackets[rb->writeIndex].pkt.len);

    rb->size++;

    int sizeIncrease = (unsigned short) (spkt.pkt.len - sizeof(tcpheader));
    printf("\033[31msize Increase in rbAdd %hu\033[0m\n", sizeIncrease);

    // printf("\033[32mAdding %hu to sending window size\033[0m\n", sizeIncrease);
    rb->sizeBytes += sizeIncrease;
    rb->writeIndex = (rb->writeIndex + 1) % rb->capacity;
    printf("ADDING PACKET TO BUFFER\n");

    return true;
}

static sentPacket *findPacket(ringbuffer *rb, unsigned int seqNo) {
    unsigned int idx = 0;
    while (rb->sentPackets[(rb->readIndex + idx) % rb->capacity].seqno != seqNo) {
        idx++;
    }

    return &rb->sentPackets[(rb->readIndex + idx) % rb->capacity];

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
        // printf("\033[32mRemoving %hu from sending window size\033[0m\n", sizeIncrease);
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
    printf("spkt init timeout %d\n", spkt.timeout);

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

void sendPktsInBfr(stcp_send_ctrl_blk *cb) {
    unsigned int idx = 0;
    while (greater32(cb->rb->size, idx)) {
        sentPacket *spkt = &cb->rb->sentPackets[(cb->rb->readIndex + idx) % cb->rb->capacity];
        sendPacket(cb->fd, spkt);
        printf("sending packet with idx %u\n", idx);
        idx++;
    }
}

unsigned int findOldestUnackedIndex(ringbuffer *rb) {
    unsigned int oldestIdx = rb->readIndex;
    long oldestTime = rb->sentPackets[rb->readIndex].timeSentMs;

    for (unsigned int i = 1; i < rb->size; i++) {
        unsigned int idx = (rb->readIndex + i) % rb->capacity;
        if (rb->sentPackets[idx].timeSentMs < oldestTime) {
            oldestTime = rb->sentPackets[idx].timeSentMs;
            oldestIdx = idx;
        }
    }

    printf("oldest packet is at idx %u\n", oldestIdx);
    return oldestIdx;
}

// return STCP_ERROR
// OR STCP_SUCCESS
int readPktsWithFastRetransmission(stcp_send_ctrl_blk *cb, int flags) {
    int len;
    int duplicateCount = 0;
    unsigned int greatestAck = cb->lastAck;
    unsigned char bfr[STCP_MTU];
    bool fastDone = false;

    printf("READ PKT WITH FAST RETRANSMISSION\n");

    while (!fastDone) {
        if (cb->rb->size == 0) return STCP_SUCCESS;
        unsigned int oldestIdx = findOldestUnackedIndex(cb->rb); // update oldest packet
        sentPacket *oldestpkt = &cb->rb->sentPackets[oldestIdx];

        // resend oldest packet if timeout occured
        printf("DEBUG: now()=%ld, timeSentMs=%ld, diff=%ld, timeout=%d\n", 
               now(), oldestpkt->timeSentMs, now() - oldestpkt->timeSentMs, oldestpkt->timeout);

        if (now() - oldestpkt->timeSentMs >= oldestpkt->timeout) {

            // note, now() returns a long, timesentMS is a long, timeout is an int
            printf("timesent %ld timeout %d\n", oldestpkt->timeSentMs, oldestpkt->timeout);
            printf("resending packet\n");
            sendPacket(cb->fd, oldestpkt);
            oldestpkt->timeout = stcpNextTimeout(oldestpkt->timeout);
            printf("updated oldestpkt timeout to %d\n", oldestpkt->timeout);
        }

        // this packet is the one we receive
        packet p;
        len = readWithTimeout(cb->fd, bfr, 5);

        if (len == STCP_READ_PERMANENT_FAILURE) return STCP_ERROR;
        if (len == STCP_READ_TIMED_OUT) continue;

        bfrToPkt(&p, bfr, len);
        if (!packetChecksum(&p, len) || !checkPktFlags(&p, flags)) continue; // ignore packet
        ntohHdr(p.hdr);

        // new cumulative ack
        if (greater32(p.hdr->ackNo, cb->lastAck)) {
            greatestAck = p.hdr->ackNo;
            removeAckdPkts(cb->rb, p.hdr->ackNo);
            cb->nextAck = plus32(p.len - sizeof(tcpheader), p.hdr->seqNo);
            duplicateCount = 0;
            cb->rwnd = p.hdr->windowSize;

        } else if (p.hdr->ackNo == cb->lastAck) {
            duplicateCount++;
            if (duplicateCount >= 3) {
                printf("\033[32mFast Retransmission\033[0m\n");

                // drain socket
                while (len != STCP_READ_TIMED_OUT) {
                    packet p;
                    len = readWithTimeout(cb->fd, bfr, 5);

                    if (len == STCP_READ_PERMANENT_FAILURE) return STCP_ERROR;
                    if (len == STCP_READ_TIMED_OUT) break; // exit while loop; socket is drained

                    bfrToPkt(&p, bfr, len);
                    if (!packetChecksum(&p, len) || !checkPktFlags(&p, flags)) continue; // ignore packet
                    ntohHdr(p.hdr);

                    // new cumulative ack found
                    if (greater32(p.hdr->ackNo, greatestAck)) {
                        greatestAck = p.hdr->ackNo;
                        fastDone = true;
                        removeAckdPkts(cb->rb, p.hdr->ackNo);
                        cb->nextAck = plus32(p.len - sizeof(tcpheader), p.hdr->seqNo);
                        duplicateCount = 0;
                        cb->rwnd = p.hdr->windowSize;
                        break; // exit read while loop;
                    }
                }
                if (fastDone) break; // fast retransmission is complete

                while (!fastDone) {

                    // resend packet
                    sentPacket *missingpkt = findPacket(cb->rb, cb->lastAck);
                    if (missingpkt != NULL) {
                        sendPacket(cb->fd, missingpkt);
                    }
                    packet p; // TODO: this definitely doesn't make a fresh packet does it
                    len = readWithTimeout(cb->fd, bfr, missingpkt->timeout);

                    if (len == STCP_READ_PERMANENT_FAILURE) return STCP_ERROR;
                    if (len == STCP_READ_TIMED_OUT) {
                        missingpkt->timeout = stcpNextTimeout(missingpkt->timeout);
                        continue;
                    }
                    bfrToPkt(&p, bfr, len);
                    if (!packetChecksum(&p, len)) continue; //ignore packet
                    ntohHdr(p.hdr);
                    if (!checkPktFlags(&p, flags)) continue; // ignore packet

                    // check it is good
                    if (greater32(p.hdr->ackNo, cb->lastAck)) {
                        greatestAck = p.hdr->ackNo;
                        fastDone = true;
                        removeAckdPkts(cb->rb, p.hdr->ackNo);
                        cb->nextAck = plus32(p.len - sizeof(tcpheader), p.hdr->seqNo);
                        duplicateCount = 0;

                        // update window size
                        cb->rwnd = p.hdr->windowSize;
                        break; // exit read while loop;
                    }

                }
            }
        }
    }
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
int stcp_send(stcp_send_ctrl_blk *stcp_CB, unsigned char* data, int length) {
    // divide up data into chunks, up to STCP_MTU + last remainder.
    // when total_size == rwnd, begin transmission

    while (length > 0) {

        // prepare all packets, add to ring buffer
        while (true) {
            unsigned short receiveWindowLeft = stcp_CB->rwnd - stcp_CB->rb->sizeBytes;
            if (receiveWindowLeft == 0) break;

            unsigned short packetSize = min(min(STCP_MSS, length), receiveWindowLeft);

            if (packetSize == 0) break;
            printf("\033[32mPacket size %hu\033[0m\n", packetSize);

            sentPacket spkt = spktInit(ACK, STCP_MAXWIN, stcp_CB->nextSeq, stcp_CB->nextAck, data, packetSize);

            if (!rbAdd(stcp_CB->rb, spkt)) break;

            data += packetSize; // increment pointer to next portion of data
            length -= packetSize; // keep track of remaining length
            stcp_CB->nextSeq = plus32(packetSize, stcp_CB->nextSeq);
            if (length <= 0) break;
        }

        sendPktsInBfr(stcp_CB);

        // printf("\033[31mReceive window size %hu sending window size %hu\033[0m\n",stcp_CB->rwnd ,stcp_CB->rb->sizeBytes);

        if (stcp_CB->rb->sizeBytes >= stcp_CB->rwnd) {
            while (stcp_CB->rb->sizeBytes >= stcp_CB->rwnd) {
                readPktsWithFastRetransmission(stcp_CB, ACK);
            }
        } else {
            readPktsWithFastRetransmission(stcp_CB, ACK);
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
    unsigned int initialSeqno = (unsigned int) rand();

    // initialize control block and ring buffer
    stcp_send_ctrl_blk *cb = cbInit(fd);

    // create syn packet
    sentPacket spkt = spktInit(SYN, STCP_MAXWIN, initialSeqno, 0, NULL, 0);

    unsigned char bfr[STCP_MTU];

    while (true) {
        sendPacket(cb->fd, &spkt);
        cb->state = STCP_SENDER_SYN_SENT;

        int len = readWithTimeout(cb->fd, bfr, spkt.timeout);

        if (len == STCP_READ_TIMED_OUT) {
            spkt.timeout = stcpNextTimeout(spkt.timeout);
            continue;
        }

        if (len == STCP_READ_PERMANENT_FAILURE) exit(EXIT_FAILURE);

        packet r;
        bfrToPkt(&r, bfr, len);

        if (!packetChecksum(&r, len)) continue; // ignore packet; packet corrupted

        ntohHdr(r.hdr);

        if (!checkPktFlags(&r, SYN | ACK) || !(r.hdr->ackNo == plus32(initialSeqno, 1))) {
            continue;
        } else {
            cb->lastAck = r.hdr->ackNo;
            cb->nextAck = plus32(r.len - sizeof(tcpheader), r.hdr->seqNo);
            cb->nextSeq = plus32(1, initialSeqno);
            cb->state = STCP_SENDER_ESTABLISHED;
            return cb;
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

    // create FIN packet
    sentPacket spkt = spktInit(FIN, STCP_MAXWIN, cb->nextSeq, cb->nextAck, NULL, 0);

    unsigned char bfr[STCP_MTU];
    cb->nextSeq = plus32(1, cb->nextSeq);

    while (true) {
        sendPacket(cb->fd, &spkt);
        cb->state = STCP_SENDER_FIN_WAIT;

        int len = readWithTimeout(cb->fd, bfr, spkt.timeout);

        if (len == STCP_READ_TIMED_OUT) {
            if (spkt.timeout == STCP_MAX_TIMEOUT) {

                close(cb->fd);
                freeCtrlBlk(cb);
                return STCP_SUCCESS; // receiver fin ack was lost; receiver in closing state
            }
            spkt.timeout = stcpNextTimeout(spkt.timeout);
            continue;
        }

        if (len == STCP_READ_PERMANENT_FAILURE) exit(EXIT_FAILURE);

        packet r;
        bfrToPkt(&r, bfr, len);

        if (!packetChecksum(&r, len)) continue; // ignore packet; packet corrupted

        ntohHdr(r.hdr);

        printf("ack %u expected ack %u\n", r.hdr->ackNo, cb->nextSeq);
        if (!checkPktFlags(&r, ACK | FIN) || !(r.hdr->ackNo == cb->nextSeq)) {
            printf("flags are wrong or we didn't get the expected ack number\n");
            continue;
        } else {
            close(cb->fd);
            freeCtrlBlk(cb);
            return STCP_SUCCESS;
        }

    }

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
        close(cb->fd);
        freeCtrlBlk(cb);
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
            close(cb->fd);
            freeCtrlBlk(cb);
            exit(EXIT_FAILURE);
        }
    }

    printf("while loop ended\n");

    /* Close the connection to remote receiver */
    if (stcp_close(cb) == STCP_ERROR) {
        close(cb->fd);
        freeCtrlBlk(cb);
    }

    return 0;
}
