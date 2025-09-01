#include "state.h"
#include "ipPacket.h"
#include "tcpPacket.h"
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
#include <algorithm>

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
    case RemoteStatus::BadPacketTcp:
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

//MSS: maximum tcp segment(data only) size.
uint32_t getMSSValue(uint32_t destAddr){
  uint32_t maxMss = getMmsR - tcpMinHeaderLen;
  uint32_t calcMss = getMtu(destAddr) - ipMinHeaderLen - tcpMinHeaderLen;
  if(calcMss > maxMss) return maxMss;
  else calcMss;
}

//effective send mss: how much tcp data are we actually allowed to send to the peer.
uint32_t getEffectiveSendMss(Tcb& b, vector<TcpOption> optionList){

  uint32_t optionListByteCount = 0;
  for(auto i = optionList.begin(); i < optionList.end(); i++){
    TcpOption o = *i;
    optionListByteCount++; //kind byte
    if(o.hasLength){
      optionListByteCount++;
    }
    optionListByteCount += o.data.size();
    
  }

  uint32_t messageSize = b.peerMss + tcpMinHeaderLen;
  uint32_t mmsS = getMmsS();
  if(mmsS < messageSize) messageSize = mmsS;
  
  return messageSize - optionListByteCount - tcpMinHeaderLen; //ipOptionByteCount is not considered because we are not setting any ip options on the raw socket.
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
  sPacket.setFlag(TcpPacketFlags::rst).setSrcPort(lP.second).setDestPort(rP.second).setSeq(seqNum).setAck(ackNum).setOptions(options).setPayload(data).setRealChecksum(lP.first, rP.first);
      
  LocalStatus ls = sendPacket(socket, rP.first, sPacket);
  return ls;
  
}

//assumes seq num, data, urgPointer and urgFlag have already been set
LocalStatus sendDataPacket(int socket, Tcb& b, TcpPacket& p){

 p.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setAck(b.rNxt).setWindow(b.rWnd).setOptions(vector<TcpOption>{}).setRealChecksum(b.lP.first, b.rP.first);
      
  LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
  return ls;
}

LocalStatus sendCurrentAck(int socket, Tcb& b){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setWindow(b.rWnd).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
  LocalStatus ls = sendPacket(socket,b.rP.first,sPacket);
  return ls;
}

LocalStatus sendSyn(int socket, Tcb& b, LocalPair lp, RemotePair rp, bool sendAck){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
     
  if(sendAck){
    sPacket.setFlag(TcpPacketFlags::ack);
    sPacket.setAck(b.rNxt);
  }
  sPacket.setFlag(TcpPacketFlags::syn).setSrcPort(lp.second).setDestPort(rp.second).setSeq(b.iss).setWindow(b.rWnd).setOptions(options).setPayload(data);
    
  if(b.myMSS != defaultMSS){
    vector<uint8_t> mss;
    loadBytes<uint16_t>(toAltOrder<uint16_t>(b.myMSS),mss);
    TcpOption(TcpOptionKind::mss, 0x4, true, mss) mssOpt;
    options.push_back(mssOpt);
    sPacket.setDataOffset(sPacket.getDataOffset() + 1); //since the mss option is 4 bytes we can cleanly add one word to offset.
  }
  
  sPacket.optionList = options;
  sPacket.setRealChecksum(lp.first, rp.first);  
  LocalStatus ls = sendPacket(socket, rp.first, sPacket);
  return ls;
}

Status ListenS::processEvent(int socket, Tcb& b, OpenEv& oe){

  bool passive = oe.passive;
  if(!passive){
    if(b.rP.first == Unspecified || b.rP.second == Unspecified){
      notifyApp(b, TcpCode::ActiveUnspec);
      return Status();
    }
    
    pickRealIsn(b);
    
    LocalStatus ls = sendSyn(socket, b, b.lP, b.rP, false);
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


void checkAndSetMSS(Tcb& b, TcpPacket& tcpP){

  for(auto i = tcpP.optionList.begin(); i < tcpP.optionList.end(); i++){
  
    TcpOption o = *i;
    if(o.kind == static_cast<uint8_t>(TcpOptionKind::mss)){
    
      uint16_t sentMss = toAltOrder<uint16_t>(unloadBytes<uint16_t>(o.data,0));
      b.peerMss = sentMss;
      break;
    }
  }

}

Status ListenS::processEvent(int socket, Tcb& b, SegmentEv& se){

  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;
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
      return Status(c, RemoteStatus::BadPacketTcp);
    }
    
    checkAndSetMSS(b, tcpP);
    
    pickRealIsn(b);
    b.irs = tcpP.getSeqNum();
    b.appNewData = b.irs;
    b.rNxt = tcpP.getSeqNum() + 1;
      
    LocalStatus ls = sendSyn(socket, b, b.lP, recPair, true);
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

  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

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
    //RFC 5961, preventing blind reset attack. 
    if(seqN != b.rNxt) return Status(RemoteStatus::MalicPacket);
    
    if(ackFlag){
      removeConn(b);
      notifyApp(b, TcpCode::ConnRst);
      return Status();
    }
    else return Status(RemoteStatus::BadPacketTcp); 
  }
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, seqN + tcpP.getSegSize(),true,0);
    }
    return Status(c,RemoteStatus::BadPacketTcp);
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn)){
  
    b.sWnd = tcpP.getWindow();
    if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
    b.sWl1 = seqN;
    b.rNxt = seqN + 1; // only syn is processed, other control or data is processed in further states
    b.irs = seqN;
    b.appNewData = b.irs;
    checkAndSetMSS(b, tcpP);
  
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      //standard connection attempt
      b.sWl2 = tcpP.getAckNum();
      b.sUna = tcpP.getAckNum(); // ack already validated earlier in method
      //TODO: remove segments that are acked from retransmission queue.
      //TODO: data or controls that were queued for transmission may be added to this packet
      LocalStatus ls = sendCurrentAck(socket, b);
      if(ls == LocalStatus::Success){
          b.currentState = EstabS();
      }
      return Status(ls);
    
    }
    else{
      //simultaneous connection attempt
      LocalStatus ls = sendSyn(socket, b, b.lP, b.rP, true);
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

  if(!verifyRecWindow(b,tcpP)){
    if(!tcpP.getFlag(TcpPacketFlags::rst)){
      
      LocalStatus ls = sendCurrentAck(socket,b);
      return Status(ls,RemoteStatus::UnexpectedPacket);
      
    }
    return Status(RemoteStatus::UnexpectedPacket);
  }
  
  return Status();
}

Status checkSaveForLater(Tcb&b, IpPacket& ipP){

  uint32_t seqNum = tcpP.getSeqNum();
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }

}

Status checkReset(int socket, Tcb& b, TcpPacket& tcpP, bool windowChecked, function<Status(int, Tcb&, TcpPacket&)> nextLogic){

  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. 
      if(!windowChecked && !verifyRecWindow(b,tcpP)) return Status(RemoteStatus::UnexpectedPacket);
      
      if(seqNum != b.rNxt){  
        LocalStatus ls = sendCurrentAck(socket,b);
        return Status(ls,RemoteStatus::MalicPacket);        
      }
      
      return nextLogic(socket,b,tcpP);
  }
  
  return Status();

}

Status remConnFlushAll(int socket, Tcb& b, TcpPacket& tcpP){
  removeConn(b);
  notifyApp(b, TcpCode::ConnRst);
  return Status();
  //TODO: flush segment queues and respond reset to outstanding receives and sends.

}
Status remConnOnly(int socket, Tcb& b, TcpPacket& tcpP){
  removeConn(b);
  return Status();
}

Status checkSec(int socket, Tcb& b, TcpPacket& tcpP, function<Status(int, Tcb&, TcpPacket&)> nextLogic){
  
  if(!checkSecurity(b,ipP)){
    LocalStatus c;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      c = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    if(c != LocalStatus::Success) return Status(c,RemoteStatus::BadPacketTcp);
    
    Status s = nextLogic(socket,b,tcpP);
    return Status(s.ls,RemoteStatus::BadPacketTcp);
  }
  
  return Status();

}

Status checkSyn(int socket, Tcb& b, TcpPacket& tcpP){

  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    //challenge ack recommended by RFC 5961  
    LocalStatus ls = sendCurrentAck(socket, b);
    return Status(ls, RemoteStatus::MalicPacket);
    
  }
  return Status();
  
}

Status checkAck(int socket, Tcb& b, TcpPacket& tcpP, function<Status(int, Tcb&, TcpPacket&)> nextLogic){
  
  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
        
      LocalStatus ls = sendCurrentAck(socket,b);
      return Status(ls,RemoteStatus::MalicPacket);
      
    }
    
    return nextLogic(socket,b,tcpP); 
    
  }
  else return Status(RemoteStatus::UnexpectedPacket);
  

}

Status establishedAckLogic(int socket, Tcb& b, TcpPacket& tcpP){

    uint32_t ackNum = tcpP.getAckNum();
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
      return Status();
            
    }
    else{
      if(ackNum > b.sNxt){
            sendCurrentAck(socket,b,tcpP);
      }
      return Status(RemoteStatus::UnexpectedPacket);
    }    
    
}

Status checkUrg(Tcb&b, TcpPacket& tcpP){

  if(tcpP.getFlag(TcpPacketFlags::urg)){
    uint32_t segUp = tcpP.getSeqNum() + tcpP.getUrg();
    if(b.rUp < segUp) b.rUp = segUp;
    if((b.rUp >= b.appNewData) && !b.urgentSignaled){
      notifyApp(TcpCode::UrgentData);
      b.urgentSignaled = true;
    }
  }
  return Status();
}

Status processData(int socket, Tcb&b, TcpPacket& tcpP){

  uint32_t seqNum = tcpP.getSeqNum();
  //at this point segment is in the window and any segment with seqNum > rNxt has been put aside for later processing.
  //This leaves two cases: either seqNum < rNxt but there is unprocessed data in the window or seqNum == rNxt
  //regardless want to start reading data at the first unprocessed byte and not reread already processed data.
  size_t beginUnProc = b.rNxt - seqNum;
  size_t index = beginUnProc;
  while((b.recBuffer.size() < recBufferMax) && (index < tcpP.payload.size())){
    b.recBuffer.push(tcpP.payload[index]);
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

  return Status();
}

Status checkFin(int socket, Tcb& b, TcpPacket& tcpP, function<Status(int, Tcb&, TcpPacket&)> nextLogic){
  
  //can only process fin if we didnt fill up the buffer with processing data and have a non zero window left.
  if(b.rWnd > 0){
    if(tcpP.getFlag(TcpPacketFlags::fin)){
      b.rNxt = b.rNxt + 1;
      //TODO: return conn closing to any pending recs and push any waiting segments.
      notifyApp(b,TcpCode::ConnClosing);
      return nextLogic(socket,b,tcpP);
    }
  }
  return Status();
}


Status SynRecS::processEvent(int socket, Tcb& b, SegmentEv& se removeConn(b);
 
  Status s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;
  
  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSaveForLater(b,ipP);
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
      
  function<LocalStatus(int, Tcb&, TcpPacket&)> secFailLogic = []{return LocalStatus::Success;};
  s = checkSec(socket,b,tcpP,secFailLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;

  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    if(b.passiveOpen){
      b.currentState = ListenS();
      return Status();
    }
    //challenge ack recommended by RFC 5961  
    LocalStatus ls = sendCurrentAck(socket,b);
    return Status(ls, RemoteStatus::MalicPacket);
    
  }
  
  function<Status(int,Tcb&,TcpPacket&)> goodAckLogic = [](int socket,Tcb& b, TcpPacket& tcpP){
    uint32_t ackNum = tcpP.getAckNum();
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
      LocalStatus c = sendReset(socket, b.lP, b.rP, 0, false, ackNum);
      return Status(c,RemoteStatus::UnexpectedPacket);
    }
  };
  s = checkAck(socket,b,tcpP,goodAckLogic);
  return s;
  
  //anything past this that needs processing will have been handed off to synchronized state
  
}

Status EstabS::processEvent(int socket, Tcb& b, SegmentEv& se){

  Status s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSaveForLater(b,ipP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkReset(socket,b,tcpP,true,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSec(socket,b,tcpP,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSyn(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;

  s = checkAck(socket,b,tcpP,establishedAckLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkUrg(b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = processData(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  function<Status(int,Tcb&,TcpPacket&)> goodFinLogic = [](int, Tcb&, TcpPacket&){
    b.currentState = CloseWaitS();
    return Status();
  }
  s = checkFin(socket,b,tcpP,goodFinLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
        
  LocalStatus ls = sendCurrentAck(socket,b);
  return Status(ls, RemoteStatus::Success); 
  
}

Status FinWait1S::processEvent(int socket, Tcb& b, SegmentEv& se){

  Status s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSaveForLater(b,ipP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkReset(socket,b,tcpP,true,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSec(socket,b,tcpP,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSyn(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkAck(socket,b,tcpP,establishedAckLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  // if we've reached this part we know ack is set and acceptable
  if(tcpP.getAckNum() == b.sNxt){
      //fin segment fully acknowledged
      b.currentState = FinWait2S();
      //TODO: futher processing in fin wait 2s
      return Status();
  }
  
  s = checkUrg(b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = processData(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  function<Status(int,Tcb&,TcpPacket&)> goodFinLogic = [](int, Tcb&, TcpPacket&){
    //if fin were acked, would have not reached this part. So fin is not acked yet.
    b.currentState = ClosingS();
    return Status();
  }
  s = checkFin(socket,b,tcpP,goodFinLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
        
  LocalStatus ls = sendCurrentAck(socket,b);
  return Status(ls, RemoteStatus::Success); 
  
}

Status FinWait2S::processEvent(int socket, Tcb& b, SegmentEv& se){

  Status s;  
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSaveForLater(b,ipP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkReset(socket,b,tcpP,true,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSec(socket,b,tcpP,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSyn(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkAck(socket,b,tcpP,establishedAckLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  if(b.retransmit.size() < 1){
      notifyApp(b,TcpCode::Ok);
  }
  
  s = checkUrg(b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = processData(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  function<Status(int,Tcb&,TcpPacket&)> goodFinLogic = [](int, Tcb&, TcpPacket&){
    //if fin were acked, would have not reached this part. So fin is not acked yet.
    b.currentState = TimeWaitS();
    return Status();
  }
  s = checkFin(socket,b,tcpP,goodFinLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
        
  LocalStatus ls = sendCurrentAck(socket,b);
  return Status(ls, RemoteStatus::Success); 
  

}

Status CloseWaitS::processEvent(int socket, Tcb& b, SegmentEv& se){

  Status s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSaveForLater(b,ipP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkReset(socket,b,tcpP,true,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSec(socket,b,tcpP,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSyn(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkAck(socket,b,tcpP,establishedAckLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  return Status(RemoteStatus::UnexpectedPacket);
}

Status ClosingS::processEvent(int socket, Tcb& b, SegmentEv& se){

  Status s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSaveForLater(b,ipP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkReset(socket,b,tcpP,true,remConnOnly);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSec(socket,b,tcpP,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSyn(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkAck(socket,b,tcpP,establishedAckLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  // if we've reached this part we know ack is set and acceptable
  if(tcpP.getAckNum() == b.sNxt){
      //fin segment fully acknowledged
      b.currentState = TimeWaitS();
      return Status();
  }
    
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  return Status(RemoteStatus::UnexpectedPacket);
}

Status LastAckS::processEvent(int socket, Tcb& b, SegmentEv& se){

  Status s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;
  
  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSaveForLater(b,ipP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkReset(socket,b,tcpP,true,remConnOnly);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSec(socket,b,tcpP,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSyn(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  function<Status(int,Tcb&,TcpPacket&)> goodAckLogic = [](int socket,Tcb& b, TcpPacket& tcpP){
    if(tcpP.getAckNum() == b.sNxt){
      removeConn(b);
      return Status();
    }
    else return Status(RemoteStatus::UnexpectedPacket);
  };
  s = checkAck(socket,b,tcpP,goodAckLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  return Status(RemoteStatus::UnexpectedPacket);
}

//TODO: investigate if timestamp RFC 6191 is worth implementing
Status TimeWaitS::processEvent(int socket, Tcb& b, SegmentEv& se){

  Status s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;
  
  s = checkSequenceNum(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
    
  s = checkReset(socket,b,tcpP,true,remConnOnly);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSec(socket,b,tcpP,remConnFlushAll);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  s = checkSyn(socket,b,tcpP);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  function<Status(int,Tcb&,TcpPacket&)> goodAckLogic = [](int socket,Tcb& b, TcpPacket& tcpP){
    if(tcpP.getAckNum() == b.sNxt){
      removeConn(b);
      return Status();
    }
    else return Status(RemoteStatus::UnexpectedPacket);
  };
  s = checkAck(socket,b,tcpP,goodAckLogic);
  if(s.ls != LocalStatus::Success || s.rs != RemoteStatus::Success) return s;
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  return Status(RemoteStatus::UnexpectedPacket);
}


Status ListenS::processEvent(int socket, Tcb& b, SendEv& se){

  if(b.rP.first == Unspecified || b.rP.second == Unspecified){
    notifyApp(b, TcpCode::ActiveUnspec);
    return Status();
  }
  
  pickRealIsn(b); 
  
  LocalStatus ls = sendSyn(socket, b, b.lP, b.rP, false);
  if(ls == LocalStatus::Success){
    b.sUna = b.iss;
    b.sNxt = b.iss + 1;
    b.passiveOpen = false;
    b.currentState = SynSentS();
    int sendBufferSize = b.sendBufferByteCount + se.data.size();
    if(sendBufferSize < sendBufferMax){
      b.sendBufferByteCount = sendBufferSize;
      b.sendBuffer.push(se); // save for later processing in established state.
    }
    else notifyApp(b, TcpCode::Resources);
    
  }
  
  return Status(ls);
  
}


bool addToSendBuffer(Tcb& b, SendEv& se){

  int sendBufferSize = b.sendBufferByteCount + se.data.size();
  if(sendBufferSize < sendBufferMax){
      b.sendBufferByteCount = sendBufferSize;
      b.sendBuffer.push(se);
      return true;
  }
  else{
      notifyApp(b, TcpCode::Resources);
      return false;
  }
  
}

Status SynSentS::processEvent(int socket, Tcb& b, SendEv& se){

    addToSendBuffer(b,se);
    return Status();

}

Status SynRecS::processEvent(int socket, Tcb& b, SendEv& se){

    addToSendBuffer(b,se);
    return Status();

}

LocalStatus segmentAndSendFrontData(int socket, Tcb& b, TcpPacket& sendPacket, bool& cont){

    uint32_t effSendMss = getEffectiveSendMss(b, vector<TcpOption>{});
    SendEv& ev = b.sendBuffer.front();

    //cant append urgent data after non urgent data: the urgent pointer will claim all the data is urgent when it is not
    if(ev.urgent && (!sendPacket.getFlag(TcpPacketFlags::urg) && (sendPacket.payload.size() > 0))){
        //send finished packet
        LocalStatus ls = sendDataPacket(socket,b,sendPacket);
        if(ls != LocalStatus::Success){
            return ls;
        }
        sendPacket = TcpPacket{};
        sendPacket.setSeqNum(b.sNxt);
    }
     
    uint32_t bytesRead = ev.bytesRead;
    bool sendMorePackets = true;
    while(sendMorePackets){
        uint32_t windowRoom = (b.sUna + b.sWnd) - b.sNxt;
        uint32_t dataRoom = static_cast<uint32_t>(ev.data.size()) - bytesRead;
        uint32_t packetRoom = effSendMSS - sendPacket.payload.size();
        uint32_t upperBound = min({packetRoom, dataRoom, windowRoom});
        for(uint32_t i = 0; i < upperBound; i++){
            sendPacket.payload.push_back(ev.data[bytesRead+i]);
            b.sNxt++;
            bytesRead++;
        }

        if(ev.urgent){
            sendPacket.setFlag(TcpPacketFlags::urg);
            sendPacket.setUrgentPointer(b.sNxt - sendPacket.getSeqNum() -1);
        }
        if(upperBound == dataRoom){
            sendMorePackets = false;
            b.sendBuffer.pop();
            b.sendBufferByteCount -= ev.data.size();
        }
        else{
            ev.bytesRead = bytesRead;
        }
          
        //peers window is filled up, sending more data would just get it rejected or dropped.
        //there might be partial data left in this data send buffer chunk
        if(upperBound == windowRoom){
            sendMorePackets = false;
            cont = false;
            LocalStatus ls = sendDataPacket(socket,b,sendPacket);
            if(ls != LocalStatus::Success){
                return ls;
            }
            sendPacket = TcpPacket{};
            sendPacket.setSeqNum(b.sNxt);
              
        }
        else{
            if(upperBound == packetRoom){
                LocalStatus ls = sendDataPacket(socket,b,sendPacket);
                sendPacket = TcpPacket{};
                sendPacket.setSeqNum(b.sNxt);
            }
              
          
        }

    }

    return LocalStatus::Success;

}

Status EstabS::processEvent(int socket, Tcb& b, SendEv& se){

  TcpPacket sendPacket;
  sendPacket.setSeqNum(b.sNxt);
  bool sendMoreData = true;
  while(!b.sendBuffer.empty() && sendMoreData){
      LocalStatus ls = segmentAndSendFrontData(socket, b, sendPacket, sendMoreData);
      if(ls != LocalStatus::Success){
          return Status(ls);
      }
  }
        
  //now that an attempt has been made to clear the buffer of already waiting data, try send(or store) the data the user just passed us.
  //might have a partially filled packet to start with
  if(sendMoreData){
      bool added = addToSendBuffer(b,se);
      if(added){
          LocalStatus ls = segmentAndSendFrontData(socket, b, sendPacket, sendMoreData);
          if(ls != LocalStatus::Success){
              return Status(ls);
          }
      }
      
  }
  else{
      addToSendBuffer(b,se);
  }
  
  return Status{};

}

Status CloseWaitS::processEvent(int socket, Tcb& b, SendEv& se){

  TcpPacket sendPacket;
  sendPacket.setSeqNum(b.sNxt);
  bool sendMoreData = true;
  while(!b.sendBuffer.empty() && sendMoreData){
      LocalStatus ls = segmentAndSendFrontData(socket, b, sendPacket, sendMoreData);
      if(ls != LocalStatus::Success){
          return Status(ls);
      }
  }
        
  //now that an attempt has been made to clear the buffer of already waiting data, try send(or store) the data the user just passed us.
  //might have a partially filled packet to start with
  if(sendMoreData){
      bool added = addToSendBuffer(b,se);
      if(added){
          LocalStatus ls = segmentAndSendFrontData(socket, b, sendPacket, sendMoreData);
          if(ls != LocalStatus::Success){
              return Status(ls);
          }
      }
      
  }
  else{
      addToSendBuffer(b,se);
  }
  
  return Status{};

}

Status FinWait1S::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing);
  return Status();
}
Status FinWait2S::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing);
  return Status();
}
Status ClosingS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing);
  return Status();
}
Status LastAckS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing);
  return Status();
}
Status TimeWaitS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing);
  return Status();
}

bool addToEventQueue(Tcb& b, Event& e){
  if(b.eventQueue.size() < eventBufferMax){
      b.eventQueue.push(e);
      return true;
  }
  else{
      notifyApp(b, TcpCode::Resources);
      return false;
  }
  
}

Status ListenS::processEvent(int socket, Tcb& b, ReceiveEv& e){

    addToEventQueue(b,e);
    return Status();

}

Status SynSentS::processEvent(int socket, Tcb& b, ReceiveEv& e){

    addToEventQueue(b,e);
    return Status();

}

Status SynRecS::processEvent(int socket, Tcb& b, ReceiveEv& e){

    addToEventQueue(b,e);
    return Status();

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


Status send(int appId, bool urgent, vector<uint8_t>& data, LocalPair lP, RemotePair rP){

  SendEv ev;
  ev.urgent = urgent;
  ev.data = data;
  
  if(connections.contains(lP)){
    if(connections[lP].contains(rP){
      Tcb& oldConn = connections[lP][rP];
      return oldConn.currentState.processEvent(socket, oldConn, ev); 
    }
  }  
  
  notifyApp(appId, TcpCode::NoConnExists);
  return Status();

}

Status receive(int appId, bool urgent, uint32_t amount, LocalPair lP, RemotePair rP){

  ReceiveEv ev;
  ev.amount = amount;
  
  if(connections.contains(lP)){
    if(connections[lP].contains(rP){
      Tcb& oldConn = connections[lP][rP];
      return oldConn.currentState.processEvent(socket, oldConn, ev); 
    }
  }  
  
  notifyApp(appId, TcpCode::NoConnExists);
  return Status();

}

Status open(int appId, bool passive, LocalPair lP, RemotePair rP, int& createdId){

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
    else{
      notifyApp(appId, TcpCode::Resources);
      return Status();
    }
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
      return oldConn.currentState.processEvent(socket, oldConn, ev); 
    }
  }
  else connections[lP] = new unordered_map<RemotePair, Tcb>();
  
  int id = pickId(s);
  pair p(LocalPair,RemotePair);
  if(id >= 0) idMap[id] = p;
  else{
    notifyApp(appId,TcpCode::Resources);
    return Status();
  }
    
  //finally need to send initial syn packet in active open because state is set to synOpen
  if(!passive){
    pickRealIsn(newConn);
  
    LocalStatus ls = sendSyn(socket,b,b.lP,b.rP,false);
    if(ls == LocalStatus::Success){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      b.currentState = SynSentS();
    }
    else{
      reclaimId(id);
      return Status(ls);
    }

    
  }
  
  newConn.id = id;
  connections[lP][rP] = newConn;
  createdId = id;
  return Status();
  
}


/*
multiplexIncoming-
Upon notification of incoming packet on interface, this method
checks details of the packet and gives it to correct connection, or sends reset if it does not belong
to a valid connection
*/

Status multiplexIncoming(int socket){

  IpPacket retPacket;
  SegmentEv ev;
  ev.ipPacket = retPacket;
  
  Status s = recPacket(socket,retPacket);
  if(s.ls == LocalStatus::Success && s.rs == RemoteStatus::Success){
    TcpPacket& p = retPacket.tcpPacket;
    uint32_t sourceAddress = retPacket.getDestAddr();
    uint32_t destAddress = retPacket.getSrcAddr();
    uint16_t sourcePort = p.getDestPort();
    uint16_t destPort = p.getSrcPort();
    
    //drop the packet, unspec values are invalid
    if(sourceAddress == Unspecified || destAddress == Unspecified || sourcePort == Unspecified || destPort == Unspecified) return Status(RemoteStatus::BadPacketTcp);
    
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
    LocalStatus ls;
    if(!p.getFlag(TcpPacketFlags::rst)){
      if(p.getFlag(TcpPacketFlags::ack)){
        ls = sendReset(socket, lP, rP, 0, false, p.getAckNum());
      }
      else{
        ls = sendReset(socket, lP, rP, p.getSeqNum() + p.getSegSize(),true,0);
      }
    }
    
    return Status(ls, RemoteStatus::UnexpectedPacket);
    
  }
  else{
    
    //only send a reset if something related to tcp was malformed.
    //If something related to ip is malformed, we never got to parsing the tcp segment so theres no point in even trying to send a reset
    //Ideally this will always be an error with tcp and not ip because the kernel checks before passing to the raw socket should drop the packet.
    if(s.rs == RemoteStatus::BadPacketTcp){
      TcpPacket& p = retPacket.tcpPacket;
      uint32_t sourceAddress = retPacket.getDestAddr();
      uint32_t destAddress = retPacket.getSrcAddr();
      uint16_t sourcePort = p.getDestPort();
      uint16_t destPort = p.getSrcPort();
    
      //either we didnt even get to parse the address info, or we did and it is invalid. Either way can't send a reset.
      if(sourceAddress == Unspecified || destAddress == Unspecified || sourcePort == Unspecified || destPort == Unspecified) return s;
    
      LocalPair lP(sourceAddress, sourcePort);
      RemotePair rP(destAddress, destPort);
      LocalStatus ls;
      if(!p.getFlag(TcpPacketFlags::rst)){
        if(p.getFlag(TcpPacketFlags::ack)){
          ls = sendReset(socket, lP, rP, 0, false, p.getAckNum());
        }
        else{
          ls = sendReset(socket, lP, rP, p.getSeqNum() + p.getSegSize(),true,0);
        }
      
        return s;
      }
    }
    
    return s; 
  }
  
}

/*
entryTcp-
Starts the tcp implementation, equivalent to a tcp module being loaded.
in the future bind this to all available source addresses and poll all of them, not just one address
*/
Status entryTcp(char* sourceAddr){

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
  
  return Status();
}

