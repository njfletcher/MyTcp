#pragma once
#include <cstdint>
#include "tcpPacket.h"
#include "ipPacket.h"
#include <utility>
#include <unordered_map>
#include <queue>
#include <memory>

#define Unspecified 0
#define keyLen 16 //128 bits = 16 bytes recommended by RFC 6528
#define dynPortStart 49152
#define dynPortEnd 65535
#define arrangedSegmentsBytesMax 500
#define recQueueMax 500
#define sendQueueBytesMax 500
#define defaultMSS 536 // maximum segment size

class Tcb;
class State;

typedef std::pair<uint32_t, uint16_t> LocalPair;
typedef std::pair<uint32_t, uint16_t> RemotePair;
typedef std::pair<LocalPair, RemotePair> ConnPair;

struct ConnHash{
  std::size_t operator()(const ConnPair& p) const;
};

typedef std::unordered_map<ConnPair, Tcb, ConnHash > ConnectionMap;

#ifdef TEST_NO_SEND
  //maps connection id to connPair
  extern std::unordered_map<int, ConnPair> idMap;
  extern ConnectionMap connections;
#endif


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
  NoConnExists = -28,
  Closing = -29
};

enum class LocalCode{
  Success = 0,
  Socket = -1
};

enum class RemoteCode{
  Success = 0,
  MalformedPacket = -1,
  UnexpectedPacket = -2

};

class Event{

  public:
    uint32_t id;
};

class OpenEv : public Event{
  public:
    bool passive;
};
class SegmentEv : public Event{
  public:
    IpPacket ipPacket;
};

class SendEv: public Event{
  public:
    std::vector<uint8_t> data;
    bool urgent;
    uint32_t bytesRead = 0;
};

class ReceiveEv: public Event{
  public:
    uint32_t amount;
    std::vector<uint8_t> providedBuffer;
};

class CloseEv: public Event{};

class AbortEv: public Event{};


class App{

  public:
    int id;
    std::deque<TcpCode> appNotifs;
    std::unordered_map<int, std::deque<TcpCode> > connNotifs;
};

class Tcb{

  public:
    Tcb(App* parApp, LocalPair l, RemotePair r, bool passive);
    Tcb() = default;
    
    int id = 0;
    App* parentApp;
    
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
    
    std::deque<ReceiveEv> recQueue;
    
    std::deque<SendEv> sendQueue;
    int sendQueueByteCount = 0;
    
    std::deque<CloseEv> closeQueue;
    
    std::shared_ptr<State> currentState;
    bool passiveOpen = false;
  
};


class State{
  
  public:
    State();
    virtual ~State();
    virtual LocalCode processEvent(int socket, Tcb& b, OpenEv& oe) = 0;
    virtual LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode) = 0;
    virtual LocalCode processEvent(int socket, Tcb& b, SendEv& se) =0;
    virtual LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se) =0;
    virtual LocalCode processEvent(int socket, Tcb& b, CloseEv& se) =0;
    virtual LocalCode processEvent(int socket, Tcb& b, AbortEv& se) =0;

};

class ListenS : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe) override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class SynSentS : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class SynRecS : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class EstabS : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class FinWait1S : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class FinWait2S : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class CloseWaitS : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class ClosingS : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class LastAckS : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

class TimeWaitS : public State{
  public:
    LocalCode processEvent(int socket, Tcb& b, OpenEv& oe)override;
    LocalCode processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode)override;
    LocalCode processEvent(int socket, Tcb& b, SendEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, ReceiveEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, CloseEv& se)override;
    LocalCode processEvent(int socket, Tcb& b, AbortEv& se)override;
};

LocalCode send(App* app, bool urgent, std::vector<uint8_t>& data, LocalPair lP, RemotePair rP);
LocalCode receive(App* app, bool urgent, uint32_t amount, LocalPair lP, RemotePair rP);
LocalCode close(App* app, LocalPair lP, RemotePair rP);
LocalCode abort(App* app, LocalPair lP, RemotePair rP);
LocalCode open(App* app, int socket, bool passive, LocalPair lP, RemotePair rP, int& createdId);
LocalCode entryTcp(char* sourceAddr);

