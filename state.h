#pragma once

#include <cstdint>
#include "packet.h"
#define keyLen 16 //128 bits = 16 bytes recommended by RFC 6528

enum class States{
  Listen,
  SynSent,
  SynRec,
  Established,
  FinWait1,
  FinWait2,
  CloseWait,
  Closing,
  LastAck,
  TimeWait,
  Closed
};

enum class Events{
  open,
  send,
  receive,
  close,
  abort,
  status
};

class Tcb{

  public:
    Tcb() = default;
    
    //all multi-byte fields are guaranteed to be in host order.
    uint32_t sourceAddress; 
    uint32_t destAddress;
    uint16_t sourcePort;
    uint16_t destPort;

    uint8_t* retransmit;
    uint8_t* currSegment;

    uint32_t sUna; // first seq num of data that has not been acknowledged by my peer.
    uint32_t sNxt; // first seq num of data that has not been sent by me.
    uint32_t sWnd; // window specified by my peer. how many bytes they can hold in buffer.
    uint32_t iss; //initial sequence number i chose for my data.
    
    uint32_t sUp; 
    uint32_t sWl1;
    uint32_t sWl2;


    uint32_t rNxt; // first seq num of data I have not received from my peer.
    uint32_t rWnd; // window advertised by me to my peer. how many bytes i can hold in buffer.
    uint32_t rUp;
    uint32_t irs; // initial sequence number chosen by peer for their data.

    uint32_t segSeq;
    uint32_t segAck;
    uint32_t segLen;
    uint32_t segWnd;
    uint32_t segUp;
  
};

int pickRealIsn(Tcb& block);
int pickInsecureIsn(Tcb& block);
int pickPrevIsn(Tcb& block, uint32_t prev);
int pickOverflowIsn(Tcb& block);

void activeOpen(char* destAddr, Tcb& b);


