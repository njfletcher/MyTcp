#include "state.h"
#include "packet.h"
#include <chrono>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "network.h"
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <poll.h>
#include <climits>
#include <functional>

using namespace std;

//range from dynPortStart to dynPortEnd
unordered_set<uint16_t> usedPorts;
//ids range from 0 to max val of int
unordered_map<int, pair<LocalPair,RemotePair>> idMap;
uint32_t bestLocalAddr;
ConnectionMap connections;

Tcb::Tcb(LocalPair l, RemotePair r, bool passive) : lP(l), rP(r), passiveOpen(passive){}
Status::Status(LocalStatus l, RemoteStatus r): ls(l), rs(r){}


void printLocalStatus(LocalStatus c){
  string s = "local status: ";
  switch(c){
    case LocalStatus::Success:
      s += "success";
      break;
    case LocalStatus::RawSocket:
      s += "error with raw socket";
      break;
    default:
      s += "unknown";
  }
  cout << s << endl;
}

void printRemoteStatus(RemoteStatus c){
  string s = "remote status: ";
  switch(c){
    case RemoteStatus::Success:
      s += "success";
      break;
    case RemoteStatus::UnexpectedPacket:
      s += "unexpected packet";
      break;
    case RemoteStatus::MalformedPacket:
      s += "malformed packet";
      break;
    case RemoteStatus::SuspectedCrash:
      s += "suspected crash";
      break;
    default:
      s += "unknown";
  }
  cout << s << endl;
}

void printTcpCode(TcpCode c){
  string s = "signal: ";
  switch(c){
    case TcpCode::ActiveUnspec:
      s += "remote socket unspecified";
      break;
    case TcpCode::Resources:
      s += "insufficient resources";
      break;
    case TcpCode::DupConn:
      s += "connection already exists";
      break;
    case TcpCode::ConnRst:
      s += "connection reset";
      break;
    case TcpCode::ConnRef:
      s += "connection refused";
      break;
    case TcpCode::ConnClosing:
      s += "connection closing";
      break;
    default:
      s += "unknown";
  }
  cout << s << endl;
}

//TODO: write code and message to file somewhere
//simulates passing a passing an info/error message to any hooked up applications.
//also a way to log errors in the program/
void notifyApp(Tcb&b, TcpCode c){
  return;
}

//TODO: research tcp security/compartment and how this check should work
bool checkSecurity(Tcb& b, IpPacket& p){
  return true;
}

bool verifyRecWindow(Tcb& b, TcpPacket& p){

  uint32_t segLen = p.getSegSize();
  uint32_t seqNum = p.getSeqNum();
  if(segLen > 0){
    if(rWnd >0){
      uint32_t lastByte = seqNum + segLen - 1;
      return ((b.rNxt <= seqNum && seqNum < (b.rNxt + b.rWnd)) || (b.rNxt <= lastByte && lastByte < (b.rNxt + b.rWnd)));
    }
    else return false;
  
  }
  else{
    if(b.rWnd > 0){
      return (b.rNxt <= seqNum && seqNum < + (b.rWnd + b.rNxt));
    }
    else{
      return (seqNum == b.rNxt);
    }
  }

}
/*
sendReset-
This method sends a rst packet, given its acknum, ackflag, and seqnum. These fields are handled
differently based on which scenario a reset is needed in, so this logic is assumed to take place
outside of this method. Any logic involving moving a connection to the next state is also
assumed to be handled outside of this method.
*/

LocalStatus sendReset(int socket, LocalPair lP, RemotePair rP, uint32_t ackNum, bool ackFlag, uint32_t seqNum){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  if(ackFlag){
    sPacket.setFlag(TcpPacketFlags::ack);
  }
  sPacket.setFlag(TcpPacketFlags::rst).setSrcPort(lP.second).setDestPort(rP.second).setSeq(seqNum).setAck(ackNum).setDataOffset(0x05).setReserved(0x00).setWindow(0x00).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(lP.first, rP.first);
      
  LocalStatus ls = sendPacket(socket, rP.first, sPacket);
  return ls;
  
}

Status ListenS::processEvent(int socket, Tcb& b, OpenEv& oe){

  vector<TcpOption> v;
  TcpPacket p;
  bool passive = oe.passive;
  if(!passive){
    if(b.rP.first == Unspecified || b.rP.second == Unspecified){
      notifyApp(b, TcpCode::ActiveUnspec);
      return Status();
    } p.setFlag(TcpPacketFlags::syn).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.iss).setAck(0x00).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(v).setRealChecksum(b.lP.first,b.rP.first);
  
    LocalStatus ls = sendPacket(socket, b.rP.first, p);
    if(ls == LocalStatus::Success){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      b.passiveOpen = false;
      b.currentState = SynSentS();
    }
    return Status(ls);
  }
  else{
    notifyApp(b, TcpCode::DupConn);
    return Status();
  }
  
}

Status SynSentS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}
Status SynRecS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}
Status EstabS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}
Status FinWait1S::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}
Status FinWait2S::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}
Status CloseWaitS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}
Status ClosingS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}
Status LastAckS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}
Status TimeWaitS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn);
  return Status();
}

Status ListenS::processEvent(int socket, Tcb& b, SegmentEv& se){

  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();
  RemotePair recPair(ipP.getSrcAddr(), tcpP.getSrcPort());
    
  //if im in the listen state, I havent sent anything, so rst could not be referring to anything valid.
  if(tcpP.getFlag(TcpPacketFlags::rst)){
    return Status(RemoteStatus::UnexpectedPacket);
  }
  
  //if im in the listen state, I havent sent anything. so any ack at all is an unacceptable ack
  if(tcpP.getFlag(TcpPacketFlags::ack)){
    LocalStatus c = sendReset(socket, b.lP, recPair, 0, false, tcpP.getAckNum());
    return Status(c,RemoteStatus::UnexpectedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn)){
  
    uint32_t segLen = tcpP.getSegSize();
    if(!checkSecurity(b, ipP)){
      LocalStatus c = sendReset(socket, b.lP, recPair, tcpP.getSeqNum() + seqLen , true, 0);
      return Status(c, RemoteStatus::MalformedPacket);
    }
    
    pickRealIsn(b);
    tcpP.irs = tcpP.getSeqNum();
    tcpP.rNxt = tcpP.getSeqNum() + 1;
      
    vector<TcpOption> options;
    vector<uint8_t> data;
    TcpPacket sPacket;
      sPacket.setFlag(TcpPacketFlags::syn).setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(recPair.second).setSeq(b.iss).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, recPair.first);
      
    LocalStatus ls = sendPacket(socket,recPair.first,sPacket);
    if(ls == LocalStatus::Success){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      b.stateLogic = SynRecS();
      if(b.rP.first == Unspecified) b.rP.first = recPair.first;
      if(b.rP.second == Unspecified) b.rP.second = recPair.second;
      //TODO 3.10.7.2 possibly trigger another event for processing of data and other control flags here: maybe forward packet without syn and ack flags set?
    }
    return Status(ls);
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);

}


Status SynSentS::processEvent(int socket, Tcb& b, SegmentEv& se){

  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();

  uint8_t ackFlag = tcpP.getFlag(TcpPacketFlags::ack);
  if(ackFlag){
    uint32_t ackN = tcpP.getAckNum();
    if(ackN <= b.iss || ackN > b.sNxt){
      if(!tcpP.getFlag(TcpPacketFlags::rst)){
        LocalStatus c = sendReset(socket, b.lP, b.rP, 0, false, ackN);
        return Status(c,RemoteStatus::UnexpectedPacket);
      }
      return Status(RemoteStatus::UnexpectedPacket);
    }
  }
    
  uint32_t seqN = tcpP.getSeqNum();
  if(tcpP.getFlag(TcpPacketFlags::rst)){
    //RFC 5961, preventing blind reset attack. TODO: research if anything else is needed.
    if(seqN != b.rNxt) return Status(RemoteStatus::MalicPacket);
    
    if(ackFlag){
      removeConn(b);
      notifyApp(b, TcpCode::ConnRst);
      return Status();
    }
    else return Status(RemoteStatus::MalformedPacket); 
    
  }
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, seqN + tcpP.getSegSize(),true,0);
    }
    return Status(c,RemoteStatus::MalformedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn)){
  
    b.sWnd = tcpP.getWindow();
    if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
    b.sWl1 = seqN;
    b.rNxt = seqN + 1; // only syn is processed, other control or data is processed in further states
    b.irs = seqN;
  
    vector<TcpOption> options;
    vector<uint8_t> data;
    TcpPacket sPacket;

    if(tcpP.getFlag(TcpPacketFlags::ack)){
      //standard connection attempt
      b.sWl2 = tcpP.getAckNum();
      b.sUna = tcpP.getAckNum(); // ack already validated earlier in method
      //TODO: remove segments that are acked from retransmission queue.
      
      //TODO: data or controls that were queued for transmission may be added to this packet
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      if(ls == LocalStatus::Success){
          b.currentState = EstabS();
      }
      return Status(ls);
    
    }
    else{
      //simultaneous connection attempt
      sPacket.setFlag(TcpPacketFlags::syn).setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.iss).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      if(ls != LocalStatus::Success){
        b.currentState = synReceived;
      }
      return Status(ls);
    }
    
  }
  //need at least a syn or a rst
  else return Status(RemoteStatus::UnexpectedPacket);
  
}

Status checkSequenceNum(int socket, Tcb& b, TcpPacket& tcpP){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  if(!verifyRecWindow(b,tcpP)){
    if(!tcpP.getFlag(TcpPacketFlags::rst)){
    sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      return Status(ls,RemoteStatus::UnexpectedPacket);
      
    }
    return Status(RemoteStatus::UnexpectedPacket);
  }
  
  return Status();
}

Status checkReset(int socket, Tcb& b, TcpPacket& tcpP, bool windowChecked, function<Status(int, Tcb&, TcpPacket&)> nextLogic){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. 
      if(!windowChecked && !verifyRecWindow(b,tcpP)) return Status(RemoteStatus::UnexpectedPacket);
      if(seqNum != b.rNxt){
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls,RemoteStatus::MalicPacket);        
      }
      
      return nextLogic(socket,b,tcpP);
  }
  
  return Status();

}

Status checkSec(int socket, Tcb& b, TcpPacket& tcpP, function<Status(int, Tcb&, TcpPacket&)> nextLogic){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    return nextLogic(socket,b,tcpP);
  }
  
  return Status();

}


Status SynRecS::processEvent(int socket, Tcb& b, SegmentEv& se){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();
  Status s;
  
  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  
  function<Status(int,Tcb&,TcpPacket&)> goodResetLogic = [](int, Tcb&, TcpPacket&){
    if(b.passiveOpen){
    b.currentState = ListenS();
    return Status();
    }
    else{
      removeConn(b);
      notifyApp(b, TcpCode::ConnRef);
      return Status();
    }
    //TODO : flush retransmission queue
  };
  
  s = checkReset(socket,b,tcpP,true,goodResetLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;

      
  
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    return Status(c, RemoteStatus::MalformedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    if(b.passiveOpen){
      b.currentState = ListenS();
      return Status();
    }
    
    //challenge ack recommended by RFC 5961  
sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
    
    LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
    return Status(ls, RemoteStatus::UnexpectedPacket);
    
  }
  
  
  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
       sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      return Status(ls,RemoteStatus::MalicPacket);
      
    }
      
    if((ackNum > b.sUna) && (ackNum <= b.sNxt)){
      b.currentState = EstabS();
      b.sWnd = tcpP.getWindow();
      if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
      b.sWl1 = tcp.getSeqNum();
      b.sWl2 = ackNum();
      //TODO trigger further processing event
      return Status();
    }
    else{
      LocalStatus c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
      return Status(c,RemoteStatus::UnexpectedPacket);
    }
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);
  
  if(tcpP.getFlag(TcpPacketFlags::fin)){
    
    b.rNxt = tcpP.getSeqNum() + 1; //advancing rNxt over fin
    sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
    if(ls == LocalStatus::Success){
      b.currentState = CloseWaitS();
      //TODO: return conn closing to any pending recs and push any waiting segments.
      notifyApp(b,TcpCode::ConnClosing);
    }
    return Status(ls);
    
  }
  
  return Status();
}

Status EstabS::processEvent(int socket, Tcb& b, SegmentEv& se){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  uint32_t seqNum = tcpP.getSeqNum();
  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();
  
  Status s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }
  
  
  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. Step 1 already handled above so seq is assumed to at least be in window.
      if(seqNum != b.rNxt){
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls,RemoteStatus::MalicPacket);        
      }
      
      removeConn(b);
      notifyApp(b, TcpCode::ConnRst);
      return Status();
      //TODO : flush retransmission queue
      
  }
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    removeConn(b);
    notifyApp(b,TcpCode::ConnRst);
    return Status(c, RemoteStatus::MalformedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    //challenge ack recommended by RFC 5961  
sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
    return Status(ls, RemoteStatus::MalicPacket);
    
  }

  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
       sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      return Status(ls, RemoteStatus::MalicPacket);
    }
      
    if((ackNum >= b.sUna) && (ackNum <= b.sNxt)){
    
      if(ackNum > b.sUna){
        b.sUna = ackNum;
        //TODO: remove acked segments from retransmission queue
        //respond ok to buffers for app
      }
      
      if((b.sWl1 < seqNum) || ((b.sWl1 == seqNum) && (b.sWl2 <= ackNum))){
        b.sWnd = tcpP.getWindow();
        if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
        b.sWl1 = seqNum;
        b.sWl2 = ackNum;
      }
            
    }
    else{
      if(ackNum > b.sNxt){
            sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls, RemoteStatus::UnexpectedPacket);
      }
      return Status(RemoteStatus::UnexpectedPacket);
    }
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);
  
  if(tcpP.getFlag(TcpPacketFlags::urg)){
    uint32_t segUp = tcpP.getUrg();
    if(b.rUp < segUp) b.rUp = segUp;
    if((b.rUp >= b.appNewData) && !b.urgentSignaled){
      notifyApp(TcpCode::UrgentData);
      b.urgentSignaled = true;
    }
  }
  
  //at this point segment is in the window and any segment with seqNum > rNxt has been put aside for later processing.
  //This leaves two cases: either seqNum < rNxt but there is unprocessed data in the window or seqNum == rNxt
  //regardless want to start reading data at the first unprocessed byte and not reread already processed data.
  size_t beginUnProc = b.rNxt - seqNum;
  size_t index = beginUnProc;
  while((recBuffer.size() < recBufferMax) && (index < tcpP.payload.size())){
    recBuffer.push(tcpP.payload[index]);
    index++;
  }

  if(index != 0 && (index == tcpP.payload.size()) && tcpP.getFlag(TcpPacketFlags::psh)){
    notifyApp(b, TcpCode::PushData);
  }
  
  uint32_t oldRightEdge = b.rNxt + b.rWnd;
  b.rNxt = b.rNxt + (index - beginUnProc);
  uint32_t leastWindow = oldRightEdge - b.rNxt;
  uint32_t bufferAvail = recBufferMax - recBuffer.size();
  if(bufferAvail >= leastWindow) b.rWnd = bufferAvail;
  else b.rWnd = leastWindow; //TODO Window management suggestions s3.8
  
  //can only process fin if we didnt fill up the buffer with processing data and have a non zero window left.
  if(b.rWnd > 0){
    if(tcpP.getFlag(TcpPacketFlags::fin)){
    
      b.rNxt = b.rNxt + 1;
      b.currentState = CloseWaitS();
      //TODO: return conn closing to any pending recs and push any waiting segments.
      notifyApp(b,TcpCode::ConnClosing);
      
    }
  }
 
  //TODO: piggy back ack with outgoing segment. 
    sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
  LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
  return Status(ls, RemoteStatus::Success); 
  

}

Status FinWait1S::processEvent(int socket, Tcb& b, SegmentEv& se){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  uint32_t seqNum = tcpP.getSeqNum();
  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();

  Status s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }
  
  
  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. Step 1 already handled above so seq is assumed to at least be in window.
      if(seqNum != b.rNxt){
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls,RemoteStatus::MalicPacket);        
      }
      
      removeConn(b);
      notifyApp(b, TcpCode::ConnRst);
      return Status();
      //TODO : flush retransmission queue
      
  }
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    removeConn(b);
    notifyApp(b,TcpCode::ConnRst);
    return Status(c, RemoteStatus::MalformedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    //challenge ack recommended by RFC 5961  
sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
    return Status(ls, RemoteStatus::MalicPacket);
    
  }

  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
       sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      return Status(ls, RemoteStatus::MalicPacket);
    }
      
    if((ackNum >= b.sUna) && (ackNum <= b.sNxt)){
    
      if(ackNum > b.sUna){
        b.sUna = ackNum;
        //TODO: remove acked segments from retransmission queue
        //respond ok to buffers for app
      }
      
      if((b.sWl1 < seqNum) || ((b.sWl1 == seqNum) && (b.sWl2 <= ackNum))){
        b.sWnd = tcpP.getWindow();
        if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
        b.sWl1 = seqNum;
        b.sWl2 = ackNum;
      }
      
      //fin segment fully acknowledged
      if(ackNum == b.sNxt){
        b.currentState = FinWait2S();
        //TODO: futher processing in fin wait 2s
        return Status();
      }
      
    }
    else{
      if(ackNum > b.sNxt){
            sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls, RemoteStatus::UnexpectedPacket);
      }
      return Status(RemoteStatus::UnexpectedPacket);
    }
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);
  
  if(tcpP.getFlag(TcpPacketFlags::urg)){
    uint32_t segUp = tcpP.getUrg();
    if(b.rUp < segUp) b.rUp = segUp;
    if((b.rUp >= b.appNewData) && !b.urgentSignaled){
      notifyApp(TcpCode::UrgentData);
      b.urgentSignaled = true;
      
    }
  }
  
  //at this point segment is in the window and any segment with seqNum > rNxt has been put aside for later processing.
  //This leaves two cases: either seqNum < rNxt but there is unprocessed data in the window or seqNum == rNxt
  //regardless want to start reading data at the first unprocessed byte and not reread already processed data.
  size_t beginUnProc = b.rNxt - seqNum;
  size_t index = beginUnProc;
  while((recBuffer.size() < recBufferMax) && (index < tcpP.payload.size())){
    recBuffer.push(tcpP.payload[index]);
    index++;
  }

  if(index != 0 && (index == tcpP.payload.size()) && tcpP.getFlag(TcpPacketFlags::psh)){
    notifyApp(b, TcpCode::PushData);
  }
  
  uint32_t oldRightEdge = b.rNxt + b.rWnd;
  b.rNxt = b.rNxt + (index - beginUnProc);
  uint32_t leastWindow = oldRightEdge - b.rNxt;
  uint32_t bufferAvail = recBufferMax - recBuffer.size();
  if(bufferAvail >= leastWindow) b.rWnd = bufferAvail;
  else b.rWnd = leastWindow; //TODO Window management suggestions s3.8
  
  //can only process fin if we didnt fill up the buffer with processing data and have a non zero window left.
  if(b.rWnd > 0){
    if(tcpP.getFlag(TcpPacketFlags::fin)){
    
      b.rNxt = b.rNxt + 1;
      b.currentState = ClosingS();
      //TODO: return conn closing to any pending recs and push any waiting segments.
      notifyApp(b,TcpCode::ConnClosing);
      //TODO: start time wait timer and end other timers.
      
    }
  }
 
  //TODO: piggy back ack with outgoing segment. 
    sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
  LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
  return Status(ls, RemoteStatus::Success); 
  

}

Status FinWait2S::processEvent(int socket, Tcb& b, SegmentEv& se){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  uint32_t seqNum = tcpP.getSeqNum();
  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();

  Status s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }
  
  
  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. Step 1 already handled above so seq is assumed to at least be in window.
      if(seqNum != b.rNxt){
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls,RemoteStatus::MalicPacket);        
      }
      
      removeConn(b);
      notifyApp(b, TcpCode::ConnRst);
      return Status();
      //TODO : flush retransmission queue
      
  }
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    removeConn(b);
    notifyApp(b,TcpCode::ConnRst);
    return Status(c, RemoteStatus::MalformedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    //challenge ack recommended by RFC 5961  
sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
    return Status(ls, RemoteStatus::MalicPacket);
    
  }

  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
       sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      return Status(ls, RemoteStatus::MalicPacket);
    }
      
    if((ackNum >= b.sUna) && (ackNum <= b.sNxt)){
    
      if(ackNum > b.sUna){
        b.sUna = ackNum;
        //TODO: remove acked segments from retransmission queue
        //respond ok to buffers for app
      }
      
      if((b.sWl1 < seqNum) || ((b.sWl1 == seqNum) && (b.sWl2 <= ackNum))){
        b.sWnd = tcpP.getWindow();
        if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
        b.sWl1 = seqNum;
        b.sWl2 = ackNum;
      }
      
      if(b.retransmit.size() < 1){
        notifyApp(b,TcpCode::Ok);
      }
      
    }
    else{
      if(ackNum > b.sNxt){
            sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls, RemoteStatus::UnexpectedPacket);
      }
      return Status(RemoteStatus::UnexpectedPacket);
    }
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);
  
  if(tcpP.getFlag(TcpPacketFlags::urg)){
    uint32_t segUp = tcpP.getUrg();
    if(b.rUp < segUp) b.rUp = segUp;
    if((b.rUp >= b.appNewData) && !b.urgentSignaled){
      notifyApp(TcpCode::UrgentData);
      b.urgentSignaled = true;
      
    }
  }
  
  //at this point segment is in the window and any segment with seqNum > rNxt has been put aside for later processing.
  //This leaves two cases: either seqNum < rNxt but there is unprocessed data in the window or seqNum == rNxt
  //regardless want to start reading data at the first unprocessed byte and not reread already processed data.
  size_t beginUnProc = b.rNxt - seqNum;
  size_t index = beginUnProc;
  while((recBuffer.size() < recBufferMax) && (index < tcpP.payload.size())){
    recBuffer.push(tcpP.payload[index]);
    index++;
  }

  if(index != 0 && (index == tcpP.payload.size()) && tcpP.getFlag(TcpPacketFlags::psh)){
    notifyApp(b, TcpCode::PushData);
  }
  
  uint32_t oldRightEdge = b.rNxt + b.rWnd;
  b.rNxt = b.rNxt + (index - beginUnProc);
  uint32_t leastWindow = oldRightEdge - b.rNxt;
  uint32_t bufferAvail = recBufferMax - recBuffer.size();
  if(bufferAvail >= leastWindow) b.rWnd = bufferAvail;
  else b.rWnd = leastWindow; //TODO Window management suggestions s3.8
  
  //can only process fin if we didnt fill up the buffer with processing data and have a non zero window left.
  if(b.rWnd > 0){
    if(tcpP.getFlag(TcpPacketFlags::fin)){
    
      b.rNxt = b.rNxt + 1;
      b.currentState = TimeWaitS();
      //TODO: return conn closing to any pending recs and push any waiting segments.
      notifyApp(b,TcpCode::ConnClosing);
      //TODO: start time wait timer and end other timers.
      
    }
  }
 
  //TODO: piggy back ack with outgoing segment. 
    sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
  LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
  return Status(ls, RemoteStatus::Success); 
  

}

Status CloseWaitS::processEvent(int socket, Tcb& b, SegmentEv& se){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  uint32_t seqNum = tcpP.getSeqNum();
  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();

  Status s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }
  
  
  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. Step 1 already handled above so seq is assumed to at least be in window.
      if(seqNum != b.rNxt){
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls,RemoteStatus::MalicPacket);        
      }
      
      removeConn(b);
      notifyApp(b, TcpCode::ConnRst);
      return Status();
      //TODO : flush retransmission queue
      
  }
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    removeConn(b);
    notifyApp(b,TcpCode::ConnRst);
    return Status(c, RemoteStatus::MalformedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    //challenge ack recommended by RFC 5961  
sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
    return Status(ls, RemoteStatus::MalicPacket);
    
  }

  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
       sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      return Status(ls, RemoteStatus::MalicPacket);
    }
      
    if((ackNum >= b.sUna) && (ackNum <= b.sNxt)){
    
      if(ackNum > b.sUna){
        b.sUna = ackNum;
        //TODO: remove acked segments from retransmission queue
        //respond ok to buffers for app
      }
      
      if((b.sWl1 < seqNum) || ((b.sWl1 == seqNum) && (b.sWl2 <= ackNum))){
        b.sWnd = tcpP.getWindow();
        if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
        b.sWl1 = seqNum;
        b.sWl2 = ackNum;
      }
            
    }
    else{
      if(ackNum > b.sNxt){
            sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls, RemoteStatus::UnexpectedPacket);
      }
      return Status(RemoteStatus::UnexpectedPacket);
    }
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  return Status(RemoteStatus::UnexpectedPacket);
}

Status ClosingS::processEvent(int socket, Tcb& b, SegmentEv& se){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  uint32_t seqNum = tcpP.getSeqNum();
  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();

  Status s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }
  
  
  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. Step 1 already handled above so seq is assumed to at least be in window.
      if(seqNum != b.rNxt){
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls,RemoteStatus::MalicPacket);        
      }
      
      removeConn(b);
      return Status();
  }
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    removeConn(b);
    notifyApp(b,TcpCode::ConnRst);
    return Status(c, RemoteStatus::MalformedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    //challenge ack recommended by RFC 5961  
sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
    return Status(ls, RemoteStatus::MalicPacket);
    
  }

  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
       sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      return Status(ls, RemoteStatus::MalicPacket);
    }
      
    if((ackNum >= b.sUna) && (ackNum <= b.sNxt)){
    
      if(ackNum > b.sUna){
        b.sUna = ackNum;
        //TODO: remove acked segments from retransmission queue
        //respond ok to buffers for app
      }
      
      if((b.sWl1 < seqNum) || ((b.sWl1 == seqNum) && (b.sWl2 <= ackNum))){
        b.sWnd = tcpP.getWindow();
        if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
        b.sWl1 = seqNum;
        b.sWl2 = ackNum;
      }
      
      //fin segment fully acknowledged
      if(ackNum == b.sNxt){
        b.currentState = TimeWaitS();
      }
      else{
        return Status(RemoteStatus::UnexpectedPacket);
      }
            
    }
    else{
      if(ackNum > b.sNxt){
            sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls, RemoteStatus::UnexpectedPacket);
      }
      return Status(RemoteStatus::UnexpectedPacket);
    }
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  return Status(RemoteStatus::UnexpectedPacket);
}

Status LastAckS::processEvent(int socket, Tcb& b, SegmentEv& se){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  uint32_t seqNum = tcpP.getSeqNum();
  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();
  
  Status s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }
  
  
  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. Step 1 already handled above so seq is assumed to at least be in window.
      if(seqNum != b.rNxt){
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls,RemoteStatus::MalicPacket);        
      }
      
      removeConn(b);
      return Status();
  }
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    removeConn(b);
    notifyApp(b,TcpCode::ConnRst);
    return Status(c, RemoteStatus::MalformedPacket);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    //challenge ack recommended by RFC 5961  
sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
    return Status(ls, RemoteStatus::MalicPacket);
    
  }

  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
       sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
      return Status(ls, RemoteStatus::MalicPacket);
    }
      
    if((ackNum >= b.sUna) && (ackNum <= b.sNxt)){
    
      if(ackNum > b.sUna){
        b.sUna = ackNum;
        //TODO: remove acked segments from retransmission queue
        //respond ok to buffers for app
      }
      
      if((b.sWl1 < seqNum) || ((b.sWl1 == seqNum) && (b.sWl2 <= ackNum))){
        b.sWnd = tcpP.getWindow();
        if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
        b.sWl1 = seqNum;
        b.sWl2 = ackNum;
      }
      
      //fin segment fully acknowledged
      if(ackNum == b.sNxt){
        removeConn(b);
        return Status();
      }
            
    }
    else{
      if(ackNum > b.sNxt){
            sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
        return Status(ls, RemoteStatus::UnexpectedPacket);
      }
      return Status(RemoteStatus::UnexpectedPacket);
    }
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  return Status(RemoteStatus::UnexpectedPacket);
}



void cleanup(int res, EVP_MD* sha256, EVP_MD_CTX* ctx, unsigned char * outdigest){

  OPENSSL_free(outdigest);
  EVP_MD_free(sha256);
  EVP_MD_CTX_free(ctx);
  
  if(res < 0){
    ERR_print_errors_fp(stderr);
  }
}

int pickRealIsn(Tcb& block){

  chrono::time_point t = chrono::system_clock::now();
  chrono::duration d = t.time_since_epoch();
  uint32_t tVal = d.count();

  unsigned char randBuffer[keyLen];
  if(RAND_bytes(randBuffer, keyLen) < 1){
    ERR_print_errors_fp(stderr);
    return -1;
  }
  unsigned char buffer[keyLen + (sizeof(block.sourceAddress) * 2) + (sizeof(block.sourcePort) * 2)];
  
  size_t i = 0;
  size_t end = sizeof(block.sourceAddress);
  for(;i < end; i++){
    size_t shift = ((sizeof(block.sourceAddress) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (block.sourceAddress & (val << shift)) >> shift;
  }
  end = end + sizeof(block.destAddress);
  for(; i < end; i++){
    size_t shift = ((sizeof(block.destAddress) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (block.destAddress & (val << shift)) >> shift;
  }
  end = end + sizeof(block.sourcePort);
  for(; i < end; i++){
    size_t shift = ((sizeof(block.sourcePort) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (block.sourcePort & (val << shift)) >> shift;
  }
  end = end + sizeof(block.destPort);
  for(; i < end; i++){
    size_t shift = ((sizeof(block.destPort) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (block.destPort & (val << shift)) >> shift;
  }

  for(size_t j = 0; j < keyLen; j++){
    buffer[i+j] = randBuffer[j];
  }
  
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if(ctx == NULL){
    cleanup(-1,NULL,ctx,NULL);
    return -1;
  }
  
  EVP_MD* sha256 = EVP_MD_fetch(NULL,"SHA256", NULL);
  if(!EVP_DigestInit_ex(ctx,sha256,NULL)){
    cleanup(-1,sha256,ctx,NULL);
    return -1;
  }
  
  if( !EVP_DigestUpdate(ctx, buffer, sizeof(buffer))){
    cleanup(-1,sha256,ctx,NULL);
    return -1;
  }
  
  unsigned char* outdigest = (unsigned char*) OPENSSL_malloc(EVP_MD_get_size(sha256));
  if(outdigest == NULL){
    cleanup(-1, sha256,ctx,outdigest);
    return -1;
  }
  
  unsigned int len = 0;
  if(!EVP_DigestFinal_ex(ctx, outdigest, &len)){
    cleanup(-1,sha256,ctx,outdigest);
    return -1;
  }
  
  cleanup(0,sha256,ctx,outdigest);
  
  if(len < 4){
    return -1;
  }
  
  uint32_t bufferTrunc = outdigest[0] | (outdigest[1] << 8) | (outdigest[2] << 16) | (outdigest[3] << 24);
  
  block.iss = tVal + bufferTrunc;
  return 0;
}

int verifyAck(uint32_t sUna, uint32_t sNxt, uint32_t ack){
  return (ack > sUna) && (ack <= sNxt);
}


/*pickDynPort 
picks an unused port from the dynamic range
if for some reason it cant find one, returns 0(unspecified)
the user should check for unspecified as an error
*/
uint16_t pickDynPort(){
  
  for(uint16_t p = dynPortStart; p <= dynPortEnd; p++){
    if(!usedPorts.contains(p)){
      usedPorts.insert(p);
      return p;
    }
  }
  return Unspecified;

}

/*pickId
picks an available id to map a connection to. 
returns -1 for error or an id for success
*/
int pickId(){
  for(0 i = 0; i <= INT_MAX; i++){
    if(!idMap.contains(i)) return i;
  }
  return -1;
}

/*
reclaimId
reclaims id so that it can be used with new connections
assumes the id is a valid one that is in use
*/
void reclaimId(int id){
  idMap.erase(id);
}

/*pickDynAddr
ideally will pick best address based on routing tables.
for right now this just returns a default address
*/
uint32_t pickDynAddr(){

  return bestLocalAddr;
}

void removeConn(Tcb& b){

  reclaimId(b.id);
  connections[b.lP].erase(rP);
  if(connections[b.lP].empty()){
    connections.erase(b.lP);
  }
  
}



/*
open
models the open action for the application interface
creates connection and kicks off handshake(if active open)
returns negative code for error or a unique identifier analogous to a file descriptor.
*/
int open(bool passive, LocalPair lP, RemotePair rP){

  OpenEv ev;
  ev.passive = passive;
  
  Tcb newConn(lP, rP, passive);
  if(passive){
    newConn.currentState = ListenS();
  }
  else{
    //unspecified remote info in active open does not make sense
    if(rP.first == Unspecified || rP.second == Unspecified) static_cast<int>(Code::ActiveUnspec);
    newConn.currentState = SynSentS();
  }
  
  if(lP.second == Unspecified){
    uint16_t chosenPort = pickDynPort();
    if(chosenPort != Unspecified){
      lP.second = chosenPort;
      newConn.lP = lP;
    }
    else return static_cast<int>(Code::Resources);
  }
  if(lP.first == Unspecified){
    uint32_t chosenAddr = pickDynAddr(); 
    lP.first = chosenAddr;
    newConn.lP = lP;
  }
  
  if(connections.contains(lP)){
    //duplicate connection
    if(connections[lP].contains(rP){
      Tcb& oldConn = connections[lP][rP];
      return static_cast<int>(oldConn.currentState.processEvent(socket, oldConn, ev); 
    }
  }
  else connections[lP] = new unordered_map<RemotePair, Tcb>();
  
  int id = pickId(s);
  pair p(LocalPair,RemotePair);
  if(id >= 0) idMap[id] = p;
  else return static_cast<int>(Code::Resources);
    
  //finally need to send initial syn packet in active open because state is set to synOpen
  if(!passive){
    pickRealIsn(newConn);
    vector<TcpOption> v;
    TcpPacket p;
   p.setFlag(TcpPacketFlags::syn).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.iss).setAck(0x00).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(v).setRealChecksum(b.lP.first,b.rP.first);
  
    if(sendPacket(socket, b.rP.first, p) != -1){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      b.currentState = SynSentS();
    }
    else{
      reclaimId(id);
      return Code::RawSend;
    }

    
  }
  
  newConn.id = id;
  connections[lP][rP] = newConn;
  return id;
  
}


/*
multiplexIncoming-
Upon notification of incoming packet on interface, this method
checks details of the packet and gives it to correct connection, or sends reset if it does not belong
to a valid connection
*/

Code multiplexIncoming(int socket){

  IpPacket retPacket;
  SegmentEv ev;
  ev.packet = retPacket;
  
  if(recPacket(socket, retPacket) != -1){
    TcpPacket& p = retPacket.getTcpPacket();

    uint32_t sourceAddress = retPacket.getDestAddr();
    uint32_t destAddress = retPacket.getSrcAddr();
    uint16_t sourcePort = p.getDestPort();
    uint16_t destPort = p.getSrcPort();
    
    //drop the packet, unspec values are invalid
    if(sourceAddress == Unspecified || destAddress == Unspecified || sourcePort == Unspecified || destPort == Unspecified) return Code::BadIncPacket;
    
    LocalPair lP(sourceAddress, sourcePort);
    RemotePair rP(destAddress, destPort);
    
    if(connections.contains(lP)){
      if(connections[lP].contains(rP)) return b.currentState.processEvent(socket,connections[lP][rP],ev);
      RemotePair addrUnspec(Unspecified, rP.second);
      if(connections[lP].contains(addrUnspec)) return b.currentState.proccessEvent(socket,connections[lP][addrUnspec],ev);
      RemotePair portUnspec(rP.first, Unspecified);
      if(connections[lP].contains(portUnspec)) return b.currentState.processEvent(socket,connections[lP][portUnspec],ev);
      RemotePair fullUnspec(Unspecified, Unspecified);
      if(connections[lP].contains(fullUnspec)) return b.currentState.processEvent(socket,connections[lP][fullUnspec],ev);
    }
    
    //if we've gotten to this point no conn exists: fictional closed state
    if(!p.getFlag(TcpPacketFlags::rst)){
      if(p.getFlag(TcpPacketFlags::ack)){
        return sendReset(socket, lP, rP, 0, false, p.getAckNum());
      }
      else{
        return sendReset(socket, lP, rP, p.getSeqNum() + p.getSegSize(),true,0);
      }
    }
    else return Code::BadIncPacket;
    
  }
  else return Code::RawSend;
  
}

/*
entryTcp-
Starts the tcp implementation, equivalent to a tcp module being loaded.
in the future bind this to all available source addresses and poll all of them, not just one address
*/
Code entryTcp(char* sourceAddr){

  uint32_t sourceAddress = toAltOrder<uint32_t>(inet_addr(sourceAddr));
  int socket =  bindSocket(sourceAddress);
  if(socket < 0){
    return Code::RawSock;
  }
  
  struct pollfd pollItem;
  pollItem.fd = socket;
  pollItem.events = POLLIN; //read
  while(true){
  
    int numRet = poll(&pollItem, 1, -1);
    if((numRet > 0) && (pollItem.revents & POLLIN)){
      multiplexIncoming(socket);
    }
  
  }
  
  return Code::Success;
}


int synReceived(Tcb& b, TcpPacket& p, int socket){

  uint32_t segLen = p.getSegSize();
  if(!verifyRecWindow(b.rWnd, b.rNxt, p.seqNum, segLen)){
    return -1;
  }
  b.rNxt = p.getSeqNum() + segLen;
    
  if(p.getFlag(TcpPacketFlags::ack)){
    if(verifyAck(b.sUna, b.sNxt, p.getAckNum()){
      b.sUna = p.getAckNum();
    }
    else{
      // either error or retransmit 
      return -1;
    }
    b.currentState = established;
    
  }
  else{
    //error or possible reset
  }
    
}

/*
  all state logic functions are functions that are called when 
  the socket receives some signal(either packet from peer or command from user) for a connection
  that is in the respective state. A non null pointer to the packet means the socket received
  a packet from the peer for the connection represented by b. A null pointer to the packet means 
  an action by a user was called for the connection represented by b.  A null pointer to a packet and 
  a none event from the user does not make sense and will result in an error.
  
  Since the fictional closed state is not a real state and represents a non existent connection,
  this logic is handled in the entry point functions(either the action functions or socket rec) themselves.

  all state functions must have Code ret, params: socket, Tcb, IpPacket*, Event, evData signature
*/







