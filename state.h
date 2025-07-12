#pragma once

#include <cstdint>
#include "packet.h"
#include <utility>

#define Unspecified 0
#define keyLen 16 //128 bits = 16 bytes recommended by RFC 6528

typedef pair<uint32_t, uint16_t> LocalPair;
typedef pair<uint32_t, uint16_t> RemotePair;
typedef unordered_map<LocalPair, unordered_map<RemotePair, Tcb> > ConnectionMap;

#define dynPortStart 49152
#define dynPortEnd 65535

//status of the fuzzer itself: did it fail and how so?
enum class LocalStatus{
  Success = 0,
  RawSocket = 1
};

//status of the tcp being fuzzed: did it fail and how so?
enum class RemoteStatus{
  Success = 0,
  UnexpectedPacket = 1,
  MalformedPacket = 2,
  SuspectedCrash = 3,
  MalicPacket = 4
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
  ActiveUnspec = -20,
  Resources = -21,
  DupConn = -22,
  ConnRst = -23,
  ConnRef = -24,
  ConnClosing = -25
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
    
    uint32_t sUp; 
    uint32_t sWl1;
    uint32_t sWl2;


    uint32_t rNxt; // first seq num of data I have not received from my peer.
    uint32_t rWnd; // window advertised by me to my peer. how many bytes i can hold in buffer.
    uint32_t rUp;
    uint32_t irs; // initial sequence number chosen by peer for their data.
    
    uint32_t maxSWnd;
    
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
};

class FinWait1S : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
};

class FinWait2S : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
};

class CloseWaitS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
};

class ClosingS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
};

class LastAckS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
};

class TimeWaitS : State{
  public:
    Code processEvent(int socket, Tcb& b, OpenEv& oe);
};

















































