/*
 * transport.c 
 *
 * CPSC4510: Project 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */

//recieve window is the range of sequence numbers which the reciever can accept at any given instant (flow control)
//uses lsiding window like TCP

//if last acknowledged sequence number 8192, recieveer willing to accpet sequence numbers of 8192 to 11263(=8192+3072-1) inclusive

//While STCP is a simplified version of TCP, it still implements a lot of the TCP finite state machine (FSM).

//All the transport layer needs to know is when there is data available on the recv queue and
//when the application has closed the connection, which is communicated via the
//stcp_wait_for_event() mechanism. 


//example, if the ACK sequence
//number is 1000 (1000 is the next byte you expect), and a segment comes in with a sequence number of
//800 and a length of 300 (i.e. ends at 1099), then you have to keep the data from 1000 to 1099. A similar
//case exists at the end of the receive window
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

//headers added by me
#include <errno.h>

//my constants
const uint16_t WINDOW_SIZE = 3072; //local recieve window, congestion window, send = min_size(local recieve, congestion) of OTHER SIDE's windows
const unsigned int MSS = 536; //max segment size = 536 bytes

//TCP states ------------ change names
enum { 
    CSTATE_ESTABLISHED,
    CSTATE_CLOSED,
    SYN_ACK_SENT,
    SYN_ACK_RECEIVED,
    SYN_SENT,
    SYN_RECEIVED,
    FIN_SENT
};    /* you should have more states */



//data structure to represent what we need to know about a segment
struct segment_t {
    tcp_seq seqNum; // need sequence number
    ssize_t size; // the segment size
    bool acked; // true if the segment has been acknolwedged
    bool fin; // true if it is a fin segment
    char* data; //points to payload
};

/* this structure is global to a mysocket descriptor */
typedef struct context_t
{
    bool_t done;    /* TRUE once connection is closed */

    unsigned int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq seqNum; //next sequence number to send
    tcp_seq recv_seqNum; //next sequence number requested
    uint16_t recv_windowSize; 

    /* any other connection-wide global variables go here */
    struct sendBuffer* sb;
    struct recvBuffer* rb;
} ctx;

//buffer sliding windows
struct sendBuffer {
    char buf[WINDOW_SIZE];
    char* segEnd; //end of the segment
    char* ack_segEnd; //end of the acknowledged segment
    tcp_seq next_seqNum;
    segment_t* segments;
};

struct recvBuffer {
    char buf[WINDOW_SIZE];
    char* segEnd; //end of the segment
    tcp_seq next_seqNum;
    segment_t* segments;
};

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
//my function definitions, walking through the steps of TCP based on class information
void initBuffers(context_t*);
int min(int, int);

tcphdr* createHandshakePacket(tcp_seq, tcp_seq, uint8_t);
bool sendHandshakePacket(mysocket_t, context_t*, tcp_seq, tcp_seq, uint8_t);
void waitHandshakePacket(mysocket_t, context_t*);

//application requests data, create and send packet
void applEvent(mysocket_t, context_t*); //event meaning application sends us a packet
tcphdr* createPacket(tcp_seq, tcp_seq, char*, size_t);
bool netwSend(mysocket_t, context_t*, char*, size_t);
void netwEvent(mysocket_t, context_t*); //event meaning network sends us a packet
void applSend(mysocket_t, context_t*, char*, size_t);

//recieving packet
void parsePacket(context_t*, char*, bool&, bool&); //bool used to check if FIN or duplicate

//NOT CLOSING RIGHT
/*
free(): double free detected in tcache 2
Aborted (core dumped)
*/
//closing connection if we recieve packet with FIN
//create FIN
// send FIN
void applClose(mysocket_t, context_t*);

//testing
void printHead(tcphdr*);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    // 3 way handshake, we request connection
    if (is_active) { //client = active, client should initiate a connection
        if (!sendHandshakePacket(sd, ctx, ctx->seqNum, 0, TH_SYN)) { errno = ECONNREFUSED; } //send SYN
        waitHandshakePacket(sd, ctx); //wait SYNACK
        if (!sendHandshakePacket(sd, ctx, ctx->seqNum, ctx->recv_seqNum + 1, TH_ACK)) { errno = ECONNREFUSED; } //send ACK
    } else { //server = passive, shoud listen for connection; they request connection, connection can go both ways
        waitHandshakePacket(sd, ctx); //wait SYN
        if (!sendHandshakePacket(sd, ctx, ctx->seqNum, ctx->recv_seqNum + 1, (TH_SYN | TH_ACK))) { errno = ECONNREFUSED; } //send SYNACK
        waitHandshakePacket(sd, ctx); //wait ACK
    }

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd); //if there was an error it will get errno will get sent here

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx); //this is causing the double free issue
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    const unsigned int MAX_SEQNUM = 255;

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    /*ctx->initial_sequence_num =;*/
    ctx->seqNum = rand() % MAX_SEQNUM + 1;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);

    while (!ctx->done)
    {
        if (ctx->connection_state == CSTATE_CLOSED) { //is state was set to closed by previous event
            ctx->done = true;
            continue;
        }

        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL); //NULL = timeout pointer, means to wait indefinitely until new data arrives. ANY_EVENT = app data, network data, or app close request events

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            applEvent(sd, ctx);
        }

        /* etc. */
        if (event & NETWORK_DATA) {
            netwEvent(sd, ctx);
        }

        if (event & APP_CLOSE_REQUESTED) {
            applClose(sd, ctx);
        }
    }
}

tcphdr* createHandshakePacket(tcp_seq seqNum, tcp_seq ackNum, uint8_t flags) {
    tcphdr* packet = (tcphdr*) malloc(sizeof(tcphdr)); //create memory for header of SYN packet
    packet->th_seq = htonl(seqNum);
    packet->th_ack = htonl(ackNum);
    packet->th_off = htons(5); //data begins 20 bytes into the packet
    packet->th_flags = flags; //packet type
    packet->th_win = htons(WINDOW_SIZE); //amount of data we (the sender) are willing to accept
    return packet;
}

tcphdr* createPacket(tcp_seq seqNum, tcp_seq ackNum, char* payload, size_t pSize) {
    unsigned int packetSize = sizeof(tcphdr) + pSize;
    tcphdr* packet = (tcphdr*)malloc(packetSize);

    packet->th_seq = htonl(seqNum);
    packet->th_ack = htonl(ackNum);
    packet->th_off = htons(5); //data begins 20 bytes into the packet
    packet->th_flags = NETWORK_DATA; //packet type
    packet->th_win = htons(WINDOW_SIZE); //amount of data we (the sender) are willing to accept
    
    //append payload to header
    memcpy((char*)packet + sizeof(tcphdr), payload, pSize); //1: destination, beginning of packet offset by header, 2: source payload, 3: size
    return packet;
}


//generic sendHandshakePacket(mysocket_t sd, context_t* ctx, tcp_seq seqNum, tcp_seq ackNum, uint8_t flags)
bool sendHandshakePacket(mysocket_t sd, context_t* ctx, tcp_seq seqNum, tcp_seq ackNum, uint8_t flags) {
    tcphdr* packet = createHandshakePacket(seqNum, ackNum, flags); //create
    ctx->seqNum++; //increase sequence number after packet creation

    //send
    ssize_t bytes_sent = stcp_network_send(sd, packet, sizeof(tcphdr), NULL); //packet is data to be sent, and the packet has no body so it has header length (20 bytes)

    if(bytes_sent > 0) { //successful send
        //change state if necessary
        if (flags == TH_SYN) {
            ctx->connection_state = SYN_SENT;
        } else if (flags == (TH_SYN | TH_ACK)) {
            ctx->connection_state = SYN_ACK_SENT;
        } else if (flags == TH_FIN) {
            ctx->connection_state = FIN_SENT;
            waitHandshakePacket(sd, ctx);
        }
        free(packet);
        return true;
    } else { //error with network send
        free(packet);
        free(ctx);
        return false;
    }
}

void waitHandshakePacket(mysocket_t sd, context_t* ctx) {
    char buf[sizeof(tcphdr)];
    stcp_wait_for_event(sd, NETWORK_DATA, NULL); //hold until network data event recieved
    ssize_t bytes_recvd = stcp_network_recv(sd, buf, MSS); //limit data recieved into buffer to MaxSegementSize
    if (bytes_recvd < sizeof(tcphdr)) { //warning here because long int compared to long unsigned int, hesitant to cast bytes_recvd to unsigned
        free(ctx);
        errno = ECONNREFUSED;
        return;
    }
    //parse recieved data
    tcphdr* packet = (tcphdr*)buf;

    //extract packet flags once
    uint8_t flags = packet->th_flags;
    //common to all types of handshake packets
    if (flags == TH_SYN || flags == (TH_ACK | TH_SYN) || flags == TH_ACK) {
        ctx->recv_seqNum = ntohl(packet->th_seq);
        ctx->recv_windowSize = ntohs(packet->th_win) > 0 ? ntohs(packet->th_win) : 1; //default size 1 if invalid window size entered
    }

    if (flags == TH_SYN) { //if only SYN flag
        ctx->connection_state = SYN_RECEIVED;
    } else if (flags == (TH_ACK | TH_SYN)) { //if flags are SYN and ACK OR'd together (format of th_flags)
        ctx->connection_state = SYN_ACK_RECEIVED;
    } else if (flags == TH_ACK) { //if only ACK flag
        if (ctx->connection_state == FIN_SENT) {
            ctx->connection_state = CSTATE_CLOSED;
        }
    }
}

void applEvent(mysocket_t sd, context_t* ctx) { //TCP recieves write(payload), sends across network
    size_t max_payload = min(MSS, ctx->recv_windowSize) - sizeof(tcphdr);
    char payload[max_payload];
    ssize_t appl_bytes_recvd = stcp_app_recv(sd, payload, max_payload);

    /* app recv testing
    printf("appl_bytes_recvd: %d\n", appl_bytes_recvd);
    printf("payload: %s\n", payload);
    */

    if (appl_bytes_recvd == 0) {
        free(ctx);
        errno = ECONNREFUSED;
        return;
    }

    netwSend(sd, ctx, payload, appl_bytes_recvd);
    waitHandshakePacket(sd, ctx); //wait for ACK
}

void applClose(mysocket_t sd, context_t* ctx) {
    if (ctx->connection_state == CSTATE_ESTABLISHED) {
        sendHandshakePacket(sd, ctx, ctx->seqNum, ctx->recv_seqNum + 1, TH_FIN);
    }

    /* state test
    printf("connection_state: %d\n", ctx->connection_state);
    */
}

void netwEvent(mysocket_t sd, context_t* ctx) { 
    bool isFIN = false;
    bool isDUP = false;
    char payload[MSS];

    ssize_t bytes_recvd = stcp_network_recv(sd, payload, MSS);
    if(bytes_recvd < sizeof(tcphdr)) { //recv error
        free(ctx);
        errno = ECONNREFUSED;
        return;
    }
    if(isFIN) {
        sendHandshakePacket(sd, ctx, ctx->seqNum, ctx->recv_seqNum + 1, TH_ACK);
        stcp_fin_received(sd);
        ctx->connection_state = CSTATE_CLOSED;
        return;
    }
    parsePacket(ctx, payload, isFIN, isDUP);
    if(isDUP) {
        sendHandshakePacket(sd, ctx, ctx->seqNum, ctx->recv_seqNum + 1, TH_ACK);
        return;
    }
    if(bytes_recvd - sizeof(tcphdr)) { //data present
        applSend(sd, ctx, payload, bytes_recvd); //send payload to application
        sendHandshakePacket(sd, ctx, ctx->seqNum, ctx->recv_seqNum + 1, TH_ACK);
    }
}

void applSend(mysocket_t sd, context_t* ctx, char* payload, size_t pSize) {
    stcp_app_send(sd, payload + sizeof(tcphdr), pSize - sizeof(tcphdr)); //send just the payload to the application
}

void parsePacket(context_t* ctx, char* payload, bool& isFIN, bool& isDUP) {
    tcphdr* header = (tcphdr*)payload;
    //if current seqNum = header sequence, it's DUP? how to check
    ctx->recv_seqNum = ntohl(header->th_seq);
    ctx->recv_windowSize = ntohs(header->th_win);
    if (header->th_flags == TH_FIN) {
        isFIN = true;
    }
}

bool netwSend(mysocket_t sd, context_t* ctx, char* payload, size_t pSize) {
    tcphdr* packet = createPacket(ctx->seqNum, ctx->recv_seqNum + 1, payload, pSize);
    ctx->seqNum += pSize;

    ssize_t bytes_sent = stcp_network_send(sd, packet, sizeof(tcphdr) + pSize, NULL);

    if (bytes_sent > 0) {
        //successfull
        free(packet);
        return true;
    } else {
        //send error
        free(packet);
        free(ctx);
        errno = ECONNREFUSED;
        return false;
    }
}

int min(int a, int b) {
    return (a < b ? a : b);
}
/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}