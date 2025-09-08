#pragma once
#include <cstdint>
#include "tcpPacket.h"
#include "ipPacket.h"
#include <utility>
#include <queue>

#define Unspecified 0
#define keyLen 16 //128 bits = 16 bytes recommended by RFC 6528
#define dynPortStart 49152
#define dynPortEnd 65535
#define arrangedSegmentsBytesMax 500
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
  BadPacketTcp = 2, // packet appears to be incorrect based on data within the packet on its own.Tcp 
  SuspectedCrash = 3,
  MalicPacket = 4, // a packet that was sent from the fuzzee could be interpreted as malicious. This could indicate their handling of rfc 5961 is incorrect.
  BadPacketIp = 5, // packet appears to be incorrect based on data within the packet on its own. IP 
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
  PushData = -27,
  NoConnExists = -28
};

class Event{};

class OpenEv : public Event{
  public:
    bool passive;
};
class SegmentEv : public Event{
  public:
    IpPacket& ipPacket;
};

class SendEv: public Event{
  public:
    vector<uint8_t> data;
    bool urgent;
    uint32_t bytesRead = 0;
};

class ReceiveEv: public Event{
  public:
    uint32_t amount;
    vector<uint8_t> providedBuffer;
};

class Tcb{

  public:
    Tcb(LocalPair l, RemotePair r, bool passive);
    
    int id = 0;
    
    //all multi-byte fields are guaranteed to be in host order.
    LocalPair lP;
    RemotePair rP;

    std::vector<TcpPacket> retransmit;
    
    uint32_t sUna = 0; // first seq num of data that has not been acknowledged by my peer.
    uint32_t sNxt = 0; // first seq num of data that has not been sent by me.
    uint32_t sWnd = 0; // window specified by my peer. how many bytes they can hold in buffer.
    uint32_t iss = 0; //initial sequence number i chose for my data.
    
    uint32_t sUp = 0; //start sequence number of urgent data in peer buffer
    uint32_t sWl1 = 0; //sequence number used for last peer window update
    uint32_t sWl2 = 0; //ack number used for last peer window update 


    uint32_t rNxt = 0; // first seq num of data I have not received from my peer.
    uint32_t rWnd = 0; // window advertised by me to my peer. how many bytes i can hold in buffer.
    uint32_t rUp = 0; //start sequence number of urgent data in my buffer
    uint32_t irs = 0; // initial sequence number chosen by peer for their data.
    
    uint32_t maxSWnd = 0;
    
    //seq num of data where app has not consumed yet.
    uint32_t appNewData = 0;
    bool urgentSignaled = false;
    bool pushSeen = false;
    
    //16 bits to match ip packet 16 bit length field.
    uint16_t peerMss = defaultMSS;
    uint16_t myMss = defaultMSS;
        
    std::deque<TcpSegmentSlice> arrangedSegments;
    int arrangedSegmentsByteCount = 0;
    
    std::queue<SendEv> sendQueue;
    int sendQueueByteCount = 0;
    

    passiveOpen = false;
  
};


class State{
  
  public:
    virSendEvStsendprocessEv
    ent(int socket, Tcb& b, OpenEv& oe);
    virtual Status processEvent(int socket, Tcb& b, SegmentEv& se);
    virtual Status processEvent(int socket, Tcb& b, SendEv& se);
    virtual Status processEvent(int socket, Tcb& b, ReceiveEv& se);

};

class ListenS : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
    Status processEvent(int socket, Tcb& b, ReceiveEv& se);
};

class SynSentS : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
    Status processEvent(int socket, Tcb& b, ReceiveEv& se);
};

class SynRecS : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
    Status processEvent(int socket, Tcb& b, ReceiveEv& se);
};

class EstabS : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
};

class FinWait1S : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
};

class FinWait2S : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
};

class CloseWaitS : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
};

class ClosingS : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
};

class LastAckS : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
};

class TimeWaitS : State{
  public:
    Status processEvent(int socket, Tcb& b, OpenEv& oe);
    Status processEvent(int socket, Tcb& b, SegmentEv& se);
    Status processEvent(int socket, Tcb& b, SendEv& se);
};

















































