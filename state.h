#pragma once

#include <cstdint>
#include "packet.h"
#include <utility>
#include <queue>

#define Unspecified 0
#define keyLen 16 //128 bits = 16 bytes recommended by RFC 6528
#define dynPortStart 49152
#define dynPortEnd 65535
#define recBufferMax 500
#define sendBufferMax 500
#define defaultMSS 536 // maximum segment size

typedef pair<uint32_t, uint16_t> LocalPair;
typedef pair<uint32_t, uint16_t> RemotePair;
typedef unordered_map<LocalPair, unordered_map<RemotePair, Tcb> > ConnectionMap;


//status of the fuzzer itself: did it fail and how so?
enum class LocalStatus{
  Success = 0,
  RawSocket = 1
};

//status of the tcp being fuzzed: did it fail and how so?
enum class RemoteStatus{
  Success = 0,
  UnexpectedPacket = 1, // packet appears to be incorrect based on where it is in the tcp state/packet sequence.
  MalformedPacket = 2, // packet appears to be incorrect based on data within the packet on its own.
  SuspectedCrash = 3,
  MalicPacket = 4 // a packet that was sent from the fuzzee could be interpreted as malicious. This could indicate their handling of rfc 5961 is incorrect.
};

class Status{
  public:
    LocalStatus ls;
    RemoteStatus rs;
    Status(LocalStatus l = LocalStatus::Success, RemoteStatus r = RemoteStatus::Success);
};


//Codes that are specified by Tcp rfcs.
//These are the codes communicated to the simulated apps, and they do not actually affect the flow of the fuzzer
enum class TcpCode{
  Ok = 0,
  ActiveUnspec = -20,
  Resources = -21,
  DupConn = -22,
  ConnRst = -23,
  ConnRef = -24,
  ConnClosing = -25,
  UrgentData = -26,
  PushData = -27
};

class Tcb{

  public:
    Tcb() = default;
    Tcb(LocalPair l, RemotePair r, bool passive);
    
    int id;
    
    //all multi-byte fields are guaranteed to be in host order.
    LocalPair lP;
    RemotePair rP;

    std::vector<TcpPacket> retransmit;
    
    uint32_t sUna; // first seq num of data that has not been acknowledged by my peer.
    uint32_t sNxt; // first seq num of data that has not been sent by me.
    uint32_t sWnd; // window specified by my peer. how many bytes they can hold in buffer.
    uint32_t iss; //initial sequence number i chose for my data.
    
    uint32_t sUp; //start sequence number of urgent data in peer buffer
    uint32_t sWl1; //sequence number used for last peer window update
    uint32_t sWl2; //ack number used for last peer window update 


    uint32_t rNxt; // first seq num of data I have not received from my peer.
    uint32_t rWnd; // window advertised by me to my peer. how many bytes i can hold in buffer.
    uint32_t rUp; //start sequence number of urgent data in my buffer
    uint32_t irs; // initial sequence number chosen by peer for their data.
    
    uint32_t maxSWnd;
    //pointer to place in buffer where app has not consumed yet.
    uint16_t appNewData;
    bool urgentSignaled;
    
    //16 bits to match ip packet 16 bit length field.
    uint16_t peerMss;
    uint16_t myMss;
    
    unordered_map<uint32_t, IpPacket> waitingPackets;
    
    std::queue<uint8_t> recBuffer;
    std::queue<uint8_t> sendBuffer;
    
    State& currentState;
    
    bool passiveOpen;
  
};


class Event{};

class OpenEv : public Event{
  public:
    bool passive;
};
class SegmentEv : public Event{
  public:
    IpPacket& packet;
};
class FurtherProcEv: public Event{
};

class State{
  public:
    virtual Code processEvent(int socket, Tcb& b, OpenEv& oe);
    virtual Code processEvent(int socket, Tcb& b, SegmentEv& se);

};

class ListenS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class SynSentS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class SynRecS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class EstabS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class FinWait1S : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class FinWait2S : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class CloseWaitS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class ClosingS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class LastAckS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

class TimeWaitS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
    Code processEvent(int socket, Tcb& b, SegmentEv& se);
};

















































