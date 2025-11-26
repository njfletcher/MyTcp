#pragma once
#include <cstdint>
#include "tcpPacket.h"
#include "ipPacket.h"
#include <utility>
#include <unordered_map>
#include <queue>
#include <memory>
#include <chrono>

const uint16_t UNSPECIFIED = 0;
const int KEY_LEN = 16; //128 bits = 16 bytes recommended by RFC 6528
const uint16_t DYN_PORT_START = 49152;
const uint16_t DYN_PORT_END = 65535;
const int ARRANGED_SEGMENTS_BYTES_MAX = 500;
const int REC_QUEUE_MAX = 500;
const int SEND_QUEUE_BYTE_MAX = 500;
const uint16_t DEFAULT_MSS = 536; // maximum segment size

class Tcb;
class State;

typedef std::pair<uint32_t, uint16_t> LocalPair;
typedef std::pair<uint32_t, uint16_t> RemotePair;
typedef std::pair<LocalPair, RemotePair> ConnPair;

struct ConnHash{
  std::size_t operator()(const ConnPair& p) const;
};

typedef std::unordered_map<ConnPair, Tcb, ConnHash > ConnectionMap;

std::unordered_map<int, ConnPair> idMap;
ConnectionMap connections;


//Codes that are specified by Tcp rfcs.
//These are the codes communicated to the simulated apps, and they do not actually affect the flow of the fuzzer
enum class TcpCode{
  OK = 0,
  ACTIVEUNSPEC = -20,
  RESOURCES = -21,
  DUPCONN = -22,
  CONNRST = -23,
  CONNREF = -24,
  CONNCLOSING = -25,
  URGENTDATA = -26,
  PUSHDATA = -27,
  NOCONNEXISTS = -28,
  CLOSING = -29
};

enum class LocalCode{
  SUCCESS = 0,
  SOCKET = -1
};

enum class RemoteCode{
  SUCCESS = 0,
  MALFORMEDPACKET = -1,
  UNEXPECTEDPACKET = -2

};

class Event{
  public:
    Event(uint32_t ident);
    uint32_t getId();
  private:
    uint32_t id;
};

class OpenEv : public Event{
  public:
    OpenEv(bool p, uint32_t id);
    bool isPassive();
  private:
    bool passive;
};
class SegmentEv : public Event{
  public:
    SegmentEv(IpPacket ipPacket, uint32_t id);
    IpPacket& getIpPacket();
  private:
    IpPacket ipPacket;
};

class SendEv: public Event{
  public:
    SendEv(std::deque<uint8_t> d, bool urg, bool psh, uint32_t id);
    std::deque<uint8_t>& getData();
    bool isUrgent();
    bool isPush();
  private:
    std::deque<uint8_t> data;
    bool urgent;
    bool push;
};

class ReceiveEv: public Event{
  public:
    ReceiveEv(uint32_t a, std::vector<uint8_t> buff, uint32_t id);
    uint32_t getAmount();
    std::vector<uint8_t>& getBuffer();
  private:
    uint32_t amount;
    std::vector<uint8_t> providedBuffer;
};

class CloseEv: public Event{
  public:
    CloseEv(uint32_t id);
};

class AbortEv: public Event{
  public:
    AbortEv(uint32_t id);
};


class App{
  public:
    App(int ident, std::deque<TcpCode> aNotif, std::unordered_map<int, std::deque<TcpCode> > cNotifs);
    int getId();
    std::deque<TcpCode>& getAppNotifs();
    std::unordered_map<int, std::deque<TcpCode> >& getConnNotifs();
  private:
    int id;
    std::deque<TcpCode> appNotifs;
    std::unordered_map<int, std::deque<TcpCode> > connNotifs;
};


/*
Using state pattern to handle state transitions and logic. 
Each State is friended by Tcb to avoid having a ton of getters/setters for the inner tcb state(ie seq nums) that do nothing and expose all the private data.
*/

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

class Tcb{

  public:
    friend class State;
    friend class ListenS;
    friend class SynSentS;
    friend class SynRecS;
    friend class EstabS;
    friend class FinWait1S;
    friend class FinWait2S;
    friend class CloseWaitS;
    friend class ClosingS;
    friend class LastAckS;
    friend class TimeWaitS;
    
    Tcb(App* parApp, LocalPair l, RemotePair r, bool passive);
    Tcb() = default;
    
    int getId();
    ConnPair getConnPair();
    
    LocalCode processEventEntry(int socket, OpenEv& oe);
    LocalCode processEventEntry(int socket, SegmentEv& se, RemoteCode& remCode);
    LocalCode processEventEntry(int socket, SendEv& se);
    LocalCode processEventEntry(int socket, ReceiveEv& re);
    LocalCode processEventEntry(int socket, CloseEv& ce);
    LocalCode processEventEntry(int socket, AbortEv& ae); 
    
    void notifyApp(TcpCode c, uint32_t eId);
    
    bool swsTimerExpired();
    bool swsTimerStopped();
    void stopSwsTimer();
    void resetSwsTimer();
    
  private:
  
    void checkAndSetPeerMSS(TcpPacket& tcpP);
    
    bool checkSecurity(IpPacket& p);
    bool verifyRecWindow(TcpPacket& p);
    LocalCode checkSequenceNum(int socket, TcpPacket& tcpP, RemoteCode& remCode);
    LocalCode checkReset(int socket, TcpPacket& tcpP, bool windowChecked, RemoteCode& remCode, bool& reset);
    LocalCode checkSec(int socket, IpPacket& ipP, RemoteCode& remCode);
    LocalCode checkSyn(int socket, TcpPacket& tcpP, RemoteCode& remCode);
    LocalCode checkAck(int socket, TcpPacket& tcpP, RemoteCode& remCode);
    LocalCode establishedAckLogic(int socket, TcpPacket& tcpP, RemoteCode& remCode);
    LocalCode checkUrg(TcpPacket& tcpP, Event& e);
    LocalCode processData(int socket, TcpPacket& tcpP);
    LocalCode checkFin(int socket, TcpPacket& tcpP, bool& fin, Event& e);
    
    bool sendReset(int socket, LocalPair lP, RemotePair rP, uint32_t ackNum, bool ackFlag, uint32_t seqNum);
    bool sendDataPacket(int socket, TcpPacket& p);
    bool sendCurrentAck(int socket);
    bool sendFin(int socket);
    bool sendSyn(int socket, LocalPair lp, RemotePair rp, bool sendAck);
    bool pickRealIsn();
    void setCurrentState(std::unique_ptr<State> s);
    bool addToSendQueue(SendEv& se);
    bool addToRecQueue(ReceiveEv& e);
    
    LocalCode processRead(ReceiveEv& e);
    LocalCode normalAbortLogic(int socket, AbortEv& e);

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
    uint16_t peerMss = DEFAULT_MSS;
    uint16_t myMss = DEFAULT_MSS;
        
    std::deque<TcpSegmentSlice> arrangedSegments;
    int arrangedSegmentsByteCount = 0;
    
    std::deque<ReceiveEv> recQueue;
    
    bool nagle = false;
    std::deque<SendEv> sendQueue;
    int sendQueueByteCount = 0;
    std::chrono::milliseconds swsTimerInterval{300};
    std::chrono::steady_clock::time_point swsTimerExpire = std::chrono::steady_clock::time_point::min();
        
    std::deque<CloseEv> closeQueue;
    
    std::unique_ptr<State> currentState;
    bool passiveOpen = false;
    
};

LocalCode send(App* app, bool urgent, std::vector<uint8_t>& data, LocalPair lP, RemotePair rP);
LocalCode receive(App* app, bool urgent, uint32_t amount, LocalPair lP, RemotePair rP);
LocalCode close(App* app, int socket, LocalPair lP, RemotePair rP);
LocalCode abort(App* app, int socket, LocalPair lP, RemotePair rP);
LocalCode open(App* app, int socket, bool passive, LocalPair lP, RemotePair rP, int& createdId);
LocalCode entryTcp(char* sourceAddr);

