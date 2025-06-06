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
    
    uint32_t iss;

    int securityLevel;
    int compartmentCat; 

    uint8_t* sendBuffer;
    uint8_t* recBuffer;

    uint8_t* retransmit;
    uint8_t* currSegment;

    uint32_t sUna;
    uint32_t sNxt;
    uint32_t sWnd;
    uint32_t sUp;
    uint32_t sWl1;
    uint32_t sWl2;


    uint32_t rNxt;
    uint32_t rWnd;
    uint32_t rUp;
    uint32_t irs;

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

IpPacket activeOpen(char* destAddr, Tcb& b);


