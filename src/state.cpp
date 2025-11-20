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
#include <memory>

using namespace std;

//range from dynPortStart to dynPortEnd
unordered_map<uint16_t,bool> usedPorts;

State::State(){}
State::~State(){}

bool Tcb::swsTimerExpired(){
  if(swsTimerExpire == std::chrono::steady_clock::time_point::min()) return false;
  return std::chrono::steady_clock::now() >= swsTimerExpire;
}
bool Tcb::swsTimerStopped(){
  return swsTimerExpire == std::chrono::steady_clock::time_point::min();
}
void Tcb::stopSwsTimer(){
  swsTimerExpire = std::chrono::steady_clock::time_point::min();
}
void Tcb::resetSwsTimer(){
  swsTimerExpire = std::chrono::steady_clock::now() + swsTimerInterval;
}

std::size_t ConnHash::operator()(const ConnPair& p) const {
  
  return std::hash<uint32_t>{}(p.first.first) ^
  (std::hash<uint16_t>{}(p.first.second) << 1) ^
  (std::hash<uint32_t>{}(p.second.first) << 2) ^
  (std::hash<uint16_t>{}(p.second.second) << 3);
}

uint32_t bestLocalAddr=1;

Tcb::Tcb(App* parApp, LocalPair l, RemotePair r, bool passive) : parentApp(parApp), lP(l), rP(r), passiveOpen(passive){}

/*pickDynPort 
picks an unused port from the dynamic range
if for some reason it cant find one, returns 0(unspecified)
the user should check for unspecified as an error
*/
uint16_t pickDynPort(){
  
  for(uint16_t p = dynPortStart; p <= dynPortEnd; p++){
    if(usedPorts.find(p) == usedPorts.end()){
      usedPorts[p] = true;
      return p;
    }
  }
  return Unspecified;

}

/*pickId
picks an available id to map a connection to. 
returns bool specifying whether it worked or not
*/
bool pickId(int& id){
  for(int i = 0; i <= INT_MAX; i++){
    if(idMap.find(i) == idMap.end()){
      id = i;
      return true;
    }
  }
  return false;
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
  ConnPair p(b.lP,b.rP);
  connections.erase(p);
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
  unsigned char buffer[keyLen + (sizeof(block.rP.first) * 2) + (sizeof(block.rP.second) * 2)];
  
  size_t i = 0;
  size_t end = sizeof(block.rP.first);
  for(;i < end; i++){
    size_t shift = ((sizeof(block.rP.first) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (block.rP.first & (val << shift)) >> shift;
  }
  end = end + sizeof(block.lP.first);
  for(; i < end; i++){
    size_t shift = ((sizeof(block.lP.first) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (block.lP.first & (val << shift)) >> shift;
  }
  end = end + sizeof(block.rP.second);
  for(; i < end; i++){
    size_t shift = ((sizeof(block.rP.second) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (block.rP.second & (val << shift)) >> shift;
  }
  end = end + sizeof(block.lP.second);
  for(; i < end; i++){
    size_t shift = ((sizeof(block.lP.second) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (block.lP.second & (val << shift)) >> shift;
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
    case TcpCode::Closing:
      s += "closing";
      break;
    default:
      s += "unknown";
  }
  cout << s << endl;
}


//simulates passing a passing an info/error message to a connection that belongs to a hooked up application.
void notifyApp(Tcb&b, TcpCode c, uint32_t eId){
  b.parentApp->connNotifs[b.id].push_back(c);
}
//simulates passing a passing an info/error message to a hooked up application that is not applicable to a made connection.
void notifyApp(App* app, TcpCode c, uint32_t eId){
  app->appNotifs.push_back(c);
}


//TODO: research tcp security/compartment and how this check should work
bool checkSecurity(Tcb& b, IpPacket& p){
  return true;
}

//MSS: maximum tcp segment(data only) size.
uint32_t getMSSValue(uint32_t destAddr){
  uint32_t maxMss = getMmsR() - tcpMinHeaderLen;
  uint32_t calcMss = getMtu(destAddr) - ipMinHeaderLen - tcpMinHeaderLen;
  if(calcMss > maxMss) return maxMss;
  else return calcMss;
}

bool verifyRecWindow(Tcb& b, TcpPacket& p){

  uint32_t segLen = p.getSegSize();
  uint32_t seqNum = p.getSeqNum();
  if(segLen > 0){
    if(b.rWnd >0){
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

bool sendReset(int socket, LocalPair lP, RemotePair rP, uint32_t ackNum, bool ackFlag, uint32_t seqNum){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  if(ackFlag){
    sPacket.setFlag(TcpPacketFlags::ack);
  }
  sPacket.setFlag(TcpPacketFlags::rst).setSrcPort(lP.second).setDestPort(rP.second).setSeq(seqNum).setAck(ackNum).setOptions(options).setPayload(data).setRealChecksum(lP.first, rP.first);
      
  return sendPacket(socket, rP.first, sPacket);
  
}

//assumes seq num, data, urgPointer and urgFlag have already been set
bool sendDataPacket(int socket, Tcb& b, TcpPacket& p){

 p.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setAck(b.rNxt).setWindow(b.rWnd).setOptions(vector<TcpOption>{}).setRealChecksum(b.lP.first, b.rP.first);
      
  return sendPacket(socket,b.rP.first,p);
}

bool sendCurrentAck(int socket, Tcb& b){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setWindow(b.rWnd).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
  return sendPacket(socket,b.rP.first,sPacket);
}

bool sendFin(int socket, Tcb& b){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  sPacket.setFlag(TcpPacketFlags::fin).setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setWindow(b.rWnd).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
  return sendPacket(socket,b.rP.first,sPacket);
  
}

bool sendSyn(int socket, Tcb& b, LocalPair lp, RemotePair rp, bool sendAck){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
     
  if(sendAck){
    sPacket.setFlag(TcpPacketFlags::ack);
    sPacket.setAck(b.rNxt);
  }
  sPacket.setFlag(TcpPacketFlags::syn).setSrcPort(lp.second).setDestPort(rp.second).setSeq(b.iss).setWindow(b.rWnd).setOptions(options).setPayload(data);
    
  if(b.myMss != defaultMSS){
    vector<uint8_t> mss;
    loadBytes<uint16_t>(toAltOrder<uint16_t>(b.myMss),mss);
    TcpOption mssOpt(static_cast<uint8_t>(TcpOptionKind::mss), 0x4, true, mss);
    options.push_back(mssOpt);
    sPacket.setDataOffset(sPacket.getDataOffset() + 1); //since the mss option is 4 bytes we can cleanly add one word to offset.
  }
  
  sPacket.optionList = options;
  sPacket.setRealChecksum(lp.first, rp.first);  
  return sendPacket(socket, rp.first, sPacket);
  
}



LocalCode ListenS::processEvent(int socket, Tcb& b, OpenEv& oe){

  bool passive = oe.passive;
  if(!passive){
    //no need to check for active unspec again, outer open call already does it
    pickRealIsn(b);
    
    bool ls = sendSyn(socket, b, b.lP, b.rP, false);
    if(ls){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      b.passiveOpen = false;
      b.currentState = make_shared<SynSentS>();
      return LocalCode::Success;
    }
    else return LocalCode::Socket;
    
  }
  else{
    notifyApp(b, TcpCode::DupConn, oe.id);
    return LocalCode::Success;
  }
  
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}
LocalCode SynRecS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}
LocalCode EstabS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}
LocalCode FinWait1S::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}
LocalCode FinWait2S::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}
LocalCode CloseWaitS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}
LocalCode ClosingS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}
LocalCode LastAckS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}
LocalCode TimeWaitS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b, TcpCode::DupConn, oe.id);
  return LocalCode::Success;
}


void checkAndSetMSS(Tcb& b, TcpPacket& tcpP){

  for(auto i = tcpP.optionList.begin(); i < tcpP.optionList.end(); i++){
  
    TcpOption o = *i;
    if(o.kind == static_cast<uint8_t>(TcpOptionKind::mss)){
    
      uint16_t sentMss = toAltOrder<uint16_t>(unloadBytes<uint16_t>(o.data.data(),0));
      b.peerMss = sentMss;
      break;
    }
  }

}

LocalCode ListenS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;
  RemotePair recPair(ipP.getSrcAddr(), tcpP.getSrcPort());
    
  //if im in the listen state, I havent sent anything, so rst could not be referring to anything valid.
  if(tcpP.getFlag(TcpPacketFlags::rst)){
    remCode = RemoteCode::UnexpectedPacket;
    return LocalCode::Success;
  }
  
  //if im in the listen state, I havent sent anything. so any ack at all is an unacceptable ack
  if(tcpP.getFlag(TcpPacketFlags::ack)){
    bool sent = sendReset(socket, b.lP, recPair, 0, false, tcpP.getAckNum());
    remCode = RemoteCode::UnexpectedPacket;
    if(!sent) return LocalCode::Socket;
    else return LocalCode::Success;
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn)){
  
    uint32_t segLen = tcpP.getSegSize();
    if(!checkSecurity(b, ipP)){
      bool sent = sendReset(socket, b.lP, recPair, tcpP.getSeqNum() + segLen , true, 0);
      remCode = RemoteCode::MalformedPacket;
      if(!sent) return LocalCode::Socket;
      else return LocalCode::Success;
    }
    
    checkAndSetMSS(b, tcpP);
    
    pickRealIsn(b);
    b.irs = tcpP.getSeqNum();
    b.appNewData = b.irs;
    b.rNxt = tcpP.getSeqNum() + 1;
      
    bool sent = sendSyn(socket, b, b.lP, recPair, true);
    if(sent){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      b.currentState = make_shared<SynRecS>();
      if(b.rP.first == Unspecified) b.rP.first = recPair.first;
      if(b.rP.second == Unspecified) b.rP.second = recPair.second;
      //TODO 3.10.7.2 possibly trigger another event for processing of data and other control flags here: maybe forward packet without syn and ack flags set?
      remCode = RemoteCode::Success;
      return LocalCode::Success;
    }
    return LocalCode::Socket;
    
  }
  else{
    remCode = RemoteCode::UnexpectedPacket;
    return LocalCode::Success;
  }

}


LocalCode SynSentS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  uint8_t ackFlag = tcpP.getFlag(TcpPacketFlags::ack);
  if(ackFlag){
    uint32_t ackN = tcpP.getAckNum();
    if(ackN <= b.iss || ackN > b.sNxt){
      remCode = RemoteCode::UnexpectedPacket;
      if(!tcpP.getFlag(TcpPacketFlags::rst)){
        bool sent = sendReset(socket, b.lP, b.rP, 0, false, ackN);
        if(!sent) return LocalCode::Socket;
        else return LocalCode::Success;
      }
      else return LocalCode::Success;
    }
  }
    
  uint32_t seqN = tcpP.getSeqNum();
  if(tcpP.getFlag(TcpPacketFlags::rst)){
    //RFC 5961, preventing blind reset attack. 
    if(seqN != b.rNxt){
      remCode = RemoteCode::UnexpectedPacket;
      return LocalCode::Success;
    }
    
    if(ackFlag){
      removeConn(b);
      notifyApp(b, TcpCode::ConnRst, se.id);
    }
    else{
      remCode = RemoteCode::UnexpectedPacket;
    }
    
    return LocalCode::Success;
  }
  
  if(!checkSecurity(b,ipP)){
    bool sent = false;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      sent = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      sent = sendReset(socket, b.lP, b.rP, seqN + tcpP.getSegSize(),true,0);
    }
    remCode = RemoteCode::MalformedPacket;
    if(!sent) return LocalCode::Socket;
    else return LocalCode::Success;
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
      bool sent = sendCurrentAck(socket, b);
      if(sent){
          b.currentState = make_shared<EstabS>();
          return LocalCode::Success;
      }
      else{
        return LocalCode::Socket;
      }
    
    }
    else{
      //simultaneous connection attempt
      bool sent = sendSyn(socket, b, b.lP, b.rP, true);
      if(sent){
        b.currentState = make_shared<SynRecS>();
        return LocalCode::Success;
      }
      else{
        return LocalCode::Socket;
      }
    }
    
  }
  //need at least a syn or a rst
  else{
    remCode = RemoteCode::UnexpectedPacket;
    return LocalCode::Success;
  }
  
}

LocalCode checkSequenceNum(int socket, Tcb& b, TcpPacket& tcpP, RemoteCode& remCode){

  if(!verifyRecWindow(b,tcpP)){
    remCode = RemoteCode::UnexpectedPacket;
    if(!tcpP.getFlag(TcpPacketFlags::rst)){
      bool sent = sendCurrentAck(socket,b);
      if(!sent) return LocalCode::Socket;
      else return LocalCode::Success;
    }
    return LocalCode::Success;
  }
  
  return LocalCode::Success;
}

/*Status checkSaveForLater(Tcb&b, IpPacket& ipP){

  uint32_t seqNum = tcpP.getSeqNum();
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }

}*/

LocalCode checkReset(int socket, Tcb& b, TcpPacket& tcpP, bool windowChecked, RemoteCode& remCode, bool& reset){

  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. 
      if(!windowChecked && !verifyRecWindow(b,tcpP)){
        remCode = RemoteCode::UnexpectedPacket;
        return LocalCode::Success;
      }
      
      if(tcpP.getSeqNum() != b.rNxt){  
        bool sent = sendCurrentAck(socket,b);
        remCode = RemoteCode::UnexpectedPacket;
        if(!sent) return LocalCode::Socket;
        else return LocalCode::Success;
      }
      
      reset = true;
  }
  
  return LocalCode::Success;

}

LocalCode remConnFlushAll(int socket, Tcb& b, TcpPacket& tcpP, Event& e){
  removeConn(b);
  notifyApp(b, TcpCode::ConnRst, e.id);
  return LocalCode::Success;
  //TODO: flush segment queues and respond reset to outstanding receives and sends.

}
LocalCode remConnOnly(int socket, Tcb& b, TcpPacket& tcpP){
  removeConn(b);
  return LocalCode::Success;
}

LocalCode checkSec(int socket, Tcb& b, IpPacket& ipP, RemoteCode& remCode){
  
  TcpPacket& tcpP = ipP.tcpPacket;
  
  if(!checkSecurity(b,ipP)){
    bool sent = false;
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      sent = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      sent = sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    remCode = RemoteCode::MalformedPacket;
    if(!sent) return LocalCode::Socket;
    
  }
  return LocalCode::Success;

}

LocalCode checkSyn(int socket, Tcb& b, TcpPacket& tcpP, RemoteCode& remCode){

  if(tcpP.getFlag(TcpPacketFlags::syn)){
  
    //challenge ack recommended by RFC 5961  
    bool sent = sendCurrentAck(socket, b);
    remCode = RemoteCode::UnexpectedPacket;
    if(!sent) return LocalCode::Socket;
    else return LocalCode::Success;
  }
  return LocalCode::Success;
  
}

LocalCode checkAck(int socket, Tcb& b, TcpPacket& tcpP, RemoteCode& remCode){
  
  if(tcpP.getFlag(TcpPacketFlags::ack)){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
        
      bool sent = sendCurrentAck(socket,b);
      remCode = RemoteCode::UnexpectedPacket;
      if(!sent) return LocalCode::Socket;
      else return LocalCode::Success;
    }
    
    return LocalCode::Success;
  }
  else{
    remCode = RemoteCode::UnexpectedPacket;
    return LocalCode::Success;
  }
  
}

LocalCode establishedAckLogic(int socket, Tcb& b, TcpPacket& tcpP, RemoteCode& remCode){

    uint32_t ackNum = tcpP.getAckNum();
    uint32_t seqNum = tcpP.getSeqNum();
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
      return LocalCode::Success;
            
    }
    else{
      remCode = RemoteCode::UnexpectedPacket;
      if(ackNum > b.sNxt){
            bool sent = sendCurrentAck(socket,b);
            if(!sent) return LocalCode::Socket;
            else return LocalCode::Success;
      }
      return LocalCode::Success;
    }    
    
}

LocalCode checkUrg(Tcb&b, TcpPacket& tcpP, Event& e){

  if(tcpP.getFlag(TcpPacketFlags::urg)){
    uint32_t segUp = tcpP.getSeqNum() + tcpP.getUrg();
    if(b.rUp < segUp) b.rUp = segUp;
    if((b.rUp >= b.appNewData) && !b.urgentSignaled){
      notifyApp(b,TcpCode::UrgentData, e.id);
      b.urgentSignaled = true;
    }
  }
  return LocalCode::Success;
}

LocalCode processData(int socket, Tcb&b, TcpPacket& tcpP){

  uint32_t seqNum = tcpP.getSeqNum();
  //at this point segment is in the window and any segment with seqNum > rNxt has been put aside for later processing.
  //This leaves two cases: either seqNum < rNxt but there is unprocessed data in the window or seqNum == rNxt
  //regardless want to start reading data at the first unprocessed byte and not reread already processed data.
  
  if(seqNum != b.arrangedSegments.back().seqNum){
    TcpSegmentSlice newSlice;
    newSlice.push == tcpP.getFlag(TcpPacketFlags::psh);
    newSlice.seqNum = seqNum;
    b.arrangedSegments.push_back(newSlice);
  }
  
  uint32_t beginUnProc = static_cast<uint32_t>(b.rNxt - seqNum);
  uint32_t index = beginUnProc;
  while((b.arrangedSegmentsByteCount < arrangedSegmentsBytesMax) && (index < static_cast<uint32_t>(tcpP.payload.size()))){
    b.arrangedSegments.back().unreadData.push(tcpP.payload[index]);
    index++;
    b.arrangedSegmentsByteCount++;
  }
  
  uint32_t oldRightEdge = b.rNxt + b.rWnd;
  b.rNxt = b.rNxt + (index - beginUnProc);
  uint32_t leastWindow = oldRightEdge - b.rNxt;
  uint32_t bufferAvail = arrangedSegmentsBytesMax - b.arrangedSegmentsByteCount;
  if(bufferAvail >= leastWindow) b.rWnd = bufferAvail;
  else b.rWnd = leastWindow; //TODO Window management suggestions s3.8

  return LocalCode::Success;
}

LocalCode checkFin(int socket, Tcb& b, TcpPacket& tcpP, bool& fin, Event& e){
  
  //can only process fin if we didnt fill up the buffer with processing data and have a non zero window left.
  if(b.rWnd > 0){
    if(tcpP.getFlag(TcpPacketFlags::fin)){
      b.rNxt = b.rNxt + 1;
      //TODO: return conn closing to any pending recs and push any waiting segments.
      notifyApp(b,TcpCode::ConnClosing, e.id);
      fin = true;
    }
  }
  return LocalCode::Success;
}


LocalCode SynRecS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){
 
  LocalCode s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;
  
  s = checkSequenceNum(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
    
  bool reset = false;
  s = checkReset(socket,b,tcpP,true, remCode, reset);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(reset){
    if(b.passiveOpen){
      b.currentState = make_shared<ListenS>();
      return LocalCode::Success;
    }
    else{
      removeConn(b);
      notifyApp(b, TcpCode::ConnRef, se.id);
      return LocalCode::Success;
    }
    //TODO : flush retransmission queue
  }
  
  s = checkSec(socket,b,ipP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;

  if(tcpP.getFlag(TcpPacketFlags::syn)){
  
    if(b.passiveOpen){
      b.currentState = make_shared<ListenS>();
      return LocalCode::Success;
    }
    //challenge ack recommended by RFC 5961  
    bool sent = sendCurrentAck(socket,b);
    remCode = RemoteCode::UnexpectedPacket;
    if(!sent) return LocalCode::Socket;
    else return LocalCode::Success;
    
  }
    
  s = checkAck(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  uint32_t ackNum = tcpP.getAckNum();
  if((ackNum > b.sUna) && (ackNum <= b.sNxt)){
    b.currentState = make_shared<EstabS>();
    b.sWnd = tcpP.getWindow();
    if(b.sWnd >= b.maxSWnd) b.maxSWnd = b.sWnd;
    b.sWl1 = tcpP.getSeqNum();
    b.sWl2 = tcpP.getAckNum();
    //TODO trigger further processing event
    return LocalCode::Success;
  }
  else{
    bool sent = sendReset(socket, b.lP, b.rP, 0, false, ackNum);
    remCode = RemoteCode::UnexpectedPacket;
    if(!sent) return LocalCode::Socket;
    else return LocalCode::Success;
  }
  
  //anything past this that needs processing will have been handed off to synchronized state
  
}

LocalCode EstabS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  
  bool reset = false;
  s = checkReset(socket,b,tcpP,true, remCode, reset);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(reset){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
  }
  
  s = checkSec(socket,b,ipP, remCode);
  if(s != LocalCode::Success) return s;
  
  if(remCode != RemoteCode::Success){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
    else return LocalCode::Success;
  }
  
  s = checkSyn(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;

  s = checkAck(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = establishedAckLogic(socket, b, tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = checkUrg(b,tcpP,se);
  if(s != LocalCode::Success) return s;
  
  s = processData(socket,b,tcpP);  
  if(s != LocalCode::Success) return s;
  
  bool fin = false;
  s = checkFin(socket,b,tcpP,fin,se);
  if(s != LocalCode::Success) return s;
  
  if(fin){
      b.currentState = make_shared<CloseWaitS>();
      return LocalCode::Success;
  }
  
  bool sent = sendCurrentAck(socket, b);
  if(!sent) return LocalCode::Socket;
  else return LocalCode::Success;
  
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  bool reset = false;
  s = checkReset(socket,b,tcpP,true, remCode, reset);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(reset){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
  }
  
  s = checkSec(socket,b, ipP, remCode);
  if(s != LocalCode::Success) return s;
  
  if(remCode != RemoteCode::Success){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
    return LocalCode::Success;
  }
  
  s = checkSyn(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = checkAck(socket,b,tcpP,remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = establishedAckLogic(socket, b, tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  // if we've reached this part we know ack is set and acceptable
  if(tcpP.getAckNum() == b.sNxt){
      //fin segment fully acknowledged
      b.currentState = make_shared<FinWait2S>();
      //TODO: futher processing in fin wait 2s
      return LocalCode::Success;
  }
  
  s = checkUrg(b,tcpP, se);
  if(s != LocalCode::Success) return s;
  
  s = processData(socket,b,tcpP);
  if(s != LocalCode::Success) return s;
  
  
  bool fin = false;
  s = checkFin(socket,b,tcpP,fin,se);
  if(s != LocalCode::Success) return s;
  
  if(fin){
      b.currentState = make_shared<ClosingS>();
      return LocalCode::Success;
  
  }
        
  bool sent = sendCurrentAck(socket,b);
  if(!sent) return LocalCode::Socket;
  else return LocalCode::Success;
  
}

LocalCode FinWait2S::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;  
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  bool reset = false;
  s = checkReset(socket,b,tcpP,true,remCode, reset);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(reset){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
  }
  
  s = checkSec(socket,b,ipP, remCode);
  if(s != LocalCode::Success) return s;
  
  if(remCode != RemoteCode::Success){  
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
    return LocalCode::Success;
  }
  
  s = checkSyn(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = checkAck(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = establishedAckLogic(socket, b, tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(b.retransmit.size() < 1){
      notifyApp(b,TcpCode::Ok, se.id);
  }
  
  s = checkUrg(b,tcpP, se);
  if(s != LocalCode::Success) return s;
  
  s = processData(socket,b,tcpP);
  if(s != LocalCode::Success) return s;
  
  bool fin = false;
  s = checkFin(socket,b,tcpP,fin,se);
  if(s != LocalCode::Success) return s;
  
  if(fin){
      b.currentState = make_shared<TimeWaitS>();
      return LocalCode::Success;
  }
        
  bool sent = sendCurrentAck(socket,b);
  if(!sent) return LocalCode::Socket;
  else return LocalCode::Success;
  
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  bool reset = false;
  s = checkReset(socket,b,tcpP,true, remCode, reset);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(reset){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
  }
  
  s = checkSec(socket,b,ipP,remCode);
  if(s != LocalCode::Success) return s;
  
  if(remCode != RemoteCode::Success){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
    return LocalCode::Success;
  }
  
  s = checkSyn(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = checkAck(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = establishedAckLogic(socket, b, tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  remCode = RemoteCode::UnexpectedPacket;
  return LocalCode::Success;
}

LocalCode ClosingS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;

  s = checkSequenceNum(socket,b,tcpP,remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;

  bool reset = false;
  s = checkReset(socket,b,tcpP,true, remCode, reset);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(reset){
    LocalCode c = remConnOnly(socket, b, tcpP);
    if(c != LocalCode::Success) return c;
  }
  
  s = checkSec(socket,b,ipP, remCode);
  if(s != LocalCode::Success) return s;
  
  if(remCode != RemoteCode::Success){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
    return LocalCode::Success;
  }
  
  s = checkSyn(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = checkAck(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = establishedAckLogic(socket, b, tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  // if we've reached this part we know ack is set and acceptable
  if(tcpP.getAckNum() == b.sNxt){
      //fin segment fully acknowledged
      b.currentState = make_shared<TimeWaitS>();
      return LocalCode::Success;
  }
    
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  remCode = RemoteCode::UnexpectedPacket;
  return LocalCode::Success;
}

LocalCode LastAckS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;
  
  s = checkSequenceNum(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  bool reset = false;
  s = checkReset(socket,b,tcpP,true,remCode, reset);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(reset){
    LocalCode c = remConnOnly(socket, b, tcpP);
    if(c != LocalCode::Success) return c;
  }
  
  s = checkSec(socket,b,ipP,remCode);
  if(s != LocalCode::Success) return s;
  
  if(remCode != RemoteCode::Success){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
    return LocalCode::Success;
  }
  
  s = checkSyn(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  

  s = checkAck(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(tcpP.getAckNum() == b.sNxt){
    removeConn(b);
    return LocalCode::Success;
  }
  else{
    remCode = RemoteCode::UnexpectedPacket;
    return LocalCode::Success;
  }
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  remCode =  RemoteCode::UnexpectedPacket;
  return LocalCode::Success;
}

//TODO: investigate if timestamp RFC 6191 is worth implementing
LocalCode TimeWaitS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.ipPacket;
  TcpPacket& tcpP = ipP.tcpPacket;
  
  s = checkSequenceNum(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
    
  bool reset = false;
  s = checkReset(socket,b,tcpP,true, remCode, reset);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(reset){
    LocalCode c = remConnOnly(socket, b, tcpP);
    if(c != LocalCode::Success) return c;
  }
  
  s = checkSec(socket,b,ipP, remCode);
  if(s != LocalCode::Success) return s;
  
  if(remCode != RemoteCode::Success){
    LocalCode c = remConnFlushAll(socket, b, tcpP, se);
    if(c != LocalCode::Success) return c;
    return LocalCode::Success;
  }
  
  s = checkSyn(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  s = checkAck(socket,b,tcpP, remCode);
  if(s != LocalCode::Success) return s;
  if(remCode != RemoteCode::Success) return LocalCode::Success;
  
  if(tcpP.getAckNum() == b.sNxt){
    removeConn(b);
    return LocalCode::Success;
  }
  else{
    remCode = RemoteCode::UnexpectedPacket;
    return LocalCode::Success;
  }
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  remCode = RemoteCode::UnexpectedPacket;
  return LocalCode::Success;
}


bool addToSendQueue(Tcb& b, SendEv& se){

  int sendQueueSize = b.sendQueueByteCount + se.data.size();
  if(sendQueueSize < sendQueueBytesMax){
      b.sendQueueByteCount = sendQueueSize;
      b.sendQueue.push_back(se);
      return true;
  }
  else{
      notifyApp(b, TcpCode::Resources, se.id);
      return false;
  }
  
}

LocalCode ListenS::processEvent(int socket, Tcb& b, SendEv& se){

  if(b.rP.first == Unspecified || b.rP.second == Unspecified){
    notifyApp(b, TcpCode::ActiveUnspec, se.id);
    return LocalCode::Success;
  }
  
  pickRealIsn(b); 
  
  bool ls = sendSyn(socket, b, b.lP, b.rP, false);
  if(ls){
    b.sUna = b.iss;
    b.sNxt = b.iss + 1;
    b.passiveOpen = false;
    b.currentState = make_shared<SynSentS>();
    addToSendQueue(b,se);
    return LocalCode::Success;
  }
  else{
    return LocalCode::Socket;
  }
  
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, SendEv& se){
    addToSendQueue(b,se);s
    return LocalCode::Success;
}

LocalCode SynRecS::processEvent(int socket, Tcb& b, SendEv& se){
    addToSendQueue(b,se);
    return LocalCode::Success;
}

LocalCode EstabS::processEvent(int socket, Tcb& b, SendEv& se){
  addToSendQueue(b,se);
  return LocalCode::Success;
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, SendEv& se){
  addToSendQueue(b,se);
  return LocalCode::Success;
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing, oe.id);
  return LocalCode::Success;
}
LocalCode FinWait2S::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing, oe.id);
  return LocalCode::Success;
}
LocalCode ClosingS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing, oe.id);
  return LocalCode::Success;
}
LocalCode LastAckS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing, oe.id);
  return LocalCode::Success;
}
LocalCode TimeWaitS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b, TcpCode::ConnClosing, oe.id);
  return LocalCode::Success;
}

bool addToRecQueue(Tcb& b, ReceiveEv& e){
  if((b.recQueue.size() + 1) < recQueueMax){
      b.recQueue.push_back(e);
      return true;
  }
  else{
      notifyApp(b, TcpCode::Resources, e.id);
      return false;
  }
  
}

LocalCode ListenS::processEvent(int socket, Tcb& b, ReceiveEv& e){

    addToRecQueue(b,e);
    return LocalCode::Success;

}

LocalCode SynSentS::processEvent(int socket, Tcb& b, ReceiveEv& e){

    addToRecQueue(b,e);
    return LocalCode::Success;

}

LocalCode SynRecS::processEvent(int socket, Tcb& b, ReceiveEv& e){

    addToRecQueue(b,e);
    return LocalCode::Success;

}

LocalCode processRead(Tcb&b, ReceiveEv& e){

    uint32_t readBytes = 0;
    if(b.arrangedSegmentsByteCount >= e.amount){
      while(readBytes < e.amount && !b.arrangedSegments.empty()){
        TcpSegmentSlice& slice = b.arrangedSegments.front();
        while(readBytes < e.amount){
          e.providedBuffer.push_back(slice.unreadData.front());
          slice.unreadData.pop();
          readBytes++;
          b.arrangedSegmentsByteCount--;
          b.appNewData++;
        }
        
        if(slice.unreadData.size() == 0){
          b.arrangedSegments.pop_front();
          if(slice.push){
            
            b.pushSeen = true;
          }
        }
        
        
      }
      
      if(b.rUp > b.appNewData){
        if(!b.urgentSignaled){
          notifyApp(b, TcpCode::UrgentData, e.id);
          b.urgentSignaled = true;
        }
      }
      else{
        b.urgentSignaled = false;
      
      }
    }
    else{
      addToRecQueue(b,e);
    }
    return LocalCode::Success;

}

LocalCode EstabS::processEvent(int socket, Tcb& b, ReceiveEv& e){

  return processRead(b,e);

}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, ReceiveEv& e){

  return processRead(b,e);

}


LocalCode FinWait2S::processEvent(int socket, Tcb& b, ReceiveEv& e){

  return processRead(b,e);

}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, ReceiveEv& e){

    if(b.arrangedSegmentsByteCount == 0){
      notifyApp(b, TcpCode::ConnClosing, e.id);
      return LocalCode::Success;
    
    }

    uint32_t readBytes = 0;
    uint32_t upperBound = b.arrangedSegmentsByteCount;
    if(upperBound > e.amount){
      upperBound = e.amount;
    }
    while(readBytes < upperBound && !b.arrangedSegments.empty()){
      TcpSegmentSlice& slice = b.arrangedSegments.front();
      while(readBytes < upperBound){
        e.providedBuffer.push_back(slice.unreadData.front());
        slice.unreadData.pop();
        readBytes++;
        b.arrangedSegmentsByteCount--;
        b.appNewData++;
      }
        
      if(slice.unreadData.size() == 0){
        b.arrangedSegments.pop_front();
        if(slice.push){
          b.pushSeen = true;
        }
      }
        
        
    }
      
    if(b.rUp > b.appNewData){
      if(!b.urgentSignaled){
        notifyApp(b, TcpCode::UrgentData, e.id);
        b.urgentSignaled = true;
      }
    }
    else{
      b.urgentSignaled = false;
    }
  
    
    return LocalCode::Success;

}


LocalCode ClosingS::processEvent(int socket, Tcb& b, ReceiveEv& e){

  notifyApp(b,TcpCode::ConnClosing, e.id);
  return LocalCode::Success;

}

LocalCode LastAckS::processEvent(int socket, Tcb& b, ReceiveEv& e){

  notifyApp(b, TcpCode::ConnClosing, e.id);
  return LocalCode::Success;

}

LocalCode TimeWaitS::processEvent(int socket, Tcb& b, ReceiveEv& e){

  notifyApp(b, TcpCode::ConnClosing, e.id);
  return LocalCode::Success;

}

LocalCode ListenS::processEvent(int socket, Tcb& b, CloseEv& e){

  for(auto iter = b.recQueue.begin(); iter < b.recQueue.end(); iter++){
    ReceiveEv& rEv = *iter;
    notifyApp(b,TcpCode::Closing, rEv.id);
  }
  removeConn(b);
  return LocalCode::Success;
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, CloseEv& e){

  for(auto iter = b.recQueue.begin(); iter < b.recQueue.end(); iter++){
    ReceiveEv& rEv = *iter;
    notifyApp(b,TcpCode::Closing,rEv.id);
  }
  
  for(auto iter = b.sendQueue.begin(); iter < b.sendQueue.end(); iter++){
    SendEv& sEv = *iter;
    notifyApp(b,TcpCode::Closing,sEv.id);
  }
  
  removeConn(b);
  return LocalCode::Success;
}

LocalCode SynRecS::processEvent(int socket, Tcb& b, CloseEv& e){

  if(b.sendQueue.empty()){
    bool ls = sendFin(socket,b);
    b.currentState = make_shared<FinWait1S>();
    if(ls) return LocalCode::Success;
    else return LocalCode::Socket;
  }
  else{
    b.closeQueue.push_back(e);
    return LocalCode::Success;
  }
  
}

LocalCode EstabS::processEvent(int socket, Tcb& b, CloseEv& e){

  if(b.sendQueue.empty()){
    bool ls = sendFin(socket,b);
    b.currentState = make_shared<FinWait1S>();
    if(ls) return LocalCode::Success;
    else return LocalCode::Socket;
  }
  else{
    b.closeQueue.push_back(e);
    b.currentState = make_shared<FinWait1S>();
    return LocalCode::Success;
  }
  
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b,TcpCode::ConnClosing, e.id);
  return LocalCode::Success;
}

LocalCode FinWait2S::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b,TcpCode::ConnClosing, e.id);
  return LocalCode::Success;
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, CloseEv& e){

  if(b.sendQueue.empty()){
    bool ls = sendFin(socket,b);
    b.currentState = make_shared<LastAckS>();
    if(ls) return LocalCode::Success;
    else return LocalCode::Socket;
  }
  else{
    b.closeQueue.push_back(e);
    b.currentState = make_shared<LastAckS>();
    return LocalCode::Success;
  }

}

LocalCode ClosingS::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b,TcpCode::ConnClosing, e.id);
  return LocalCode::Success;
}

LocalCode LastAckS::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b,TcpCode::ConnClosing, e.id);
  return LocalCode::Success;
}

LocalCode TimeWaitS::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b,TcpCode::ConnClosing, e.id);
  return LocalCode::Success;
}


LocalCode ListenS::processEvent(int socket, Tcb& b, AbortEv& e){

  for(auto iter = b.recQueue.begin(); iter < b.recQueue.end(); iter++){
    ReceiveEv& rEv = *iter;
    notifyApp(b,TcpCode::ConnRst,e.id);
  }
  removeConn(b);
  return LocalCode::Success;
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, AbortEv& e){

  for(auto iter = b.recQueue.begin(); iter < b.recQueue.end(); iter++){
    ReceiveEv& rEv = *iter;
    notifyApp(b,TcpCode::ConnRst,rEv.id);
  }
  
  for(auto iter = b.sendQueue.begin(); iter < b.sendQueue.end(); iter++){
    SendEv& sEv = *iter;
    notifyApp(b,TcpCode::ConnRst,sEv.id);
  }
  
  removeConn(b);
  return LocalCode::Success;
}

LocalCode normalAbortLogic(int socket, Tcb& b, AbortEv& e){

  bool ls = sendReset(socket, b.lP, b.rP, 0, false, b.sNxt);
  
  for(auto iter = b.recQueue.begin(); iter < b.recQueue.end(); iter++){
    ReceiveEv& rEv = *iter;
    notifyApp(b,TcpCode::ConnRst,rEv.id);
  }
  
  for(auto iter = b.sendQueue.begin(); iter < b.sendQueue.end(); iter++){
    SendEv& sEv = *iter;
    notifyApp(b,TcpCode::ConnRst,sEv.id);
  }
  b.retransmit.clear();
  removeConn(b);
  if(ls) return LocalCode::Success;
  else return LocalCode::Socket;

}



LocalCode SynRecS::processEvent(int socket, Tcb& b, AbortEv& e){

  return normalAbortLogic(socket,b,e);
  
}

LocalCode EstabS::processEvent(int socket, Tcb& b, AbortEv& e){

  return normalAbortLogic(socket,b,e);
  
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, AbortEv& e){

  return normalAbortLogic(socket,b,e);
  
}

LocalCode FinWait2S::processEvent(int socket, Tcb& b, AbortEv& e){

  return normalAbortLogic(socket,b,e);
  
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, AbortEv& e){

  return normalAbortLogic(socket,b,e);
  
}

LocalCode ClosingS::processEvent(int socket, Tcb& b, AbortEv& e){
  notifyApp(b,TcpCode::Ok, e.id);
  return LocalCode::Success;
}

LocalCode LastAckS::processEvent(int socket, Tcb& b, AbortEv& e){
  notifyApp(b,TcpCode::Ok, e.id);
  return LocalCode::Success;
}

LocalCode TimeWaitS::processEvent(int socket, Tcb& b, AbortEv& e){
  notifyApp(b,TcpCode::Ok, e.id);
  return LocalCode::Success;
}


LocalCode send(App* app, int socket, bool urgent, vector<uint8_t>& data, LocalPair lP, RemotePair rP, bool push, uint32_t timeout){

  SendEv ev;
  ev.urgent = urgent;
  ev.data = data;
  ev.push = push;
  ConnPair p(lP,rP);
  
  if(connections.find(p) != connections.end()){
    Tcb& oldConn = connections[p];
    return oldConn.currentState->processEvent(socket, oldConn, ev); 
  }  
  
  notifyApp(app,TcpCode::NoConnExists, ev.id);
  return LocalCode::Success;

}

LocalCode receive(App* app, int socket, bool urgent, uint32_t amount, LocalPair lP, RemotePair rP){

  ReceiveEv ev;
  ev.amount = amount;
  
  ConnPair p(lP, rP);
  if(connections.find(p) != connections.end()){
      Tcb& oldConn = connections[p];
      return oldConn.currentState->processEvent(socket, oldConn, ev); 
  }  
  
  notifyApp(app, TcpCode::NoConnExists, ev.id);
  return LocalCode::Success;

}

LocalCode close(App* app, int socket, LocalPair lP, RemotePair rP){

  CloseEv ev;
  
  ConnPair p(lP, rP);
  if(connections.find(p) != connections.end()){
      Tcb& oldConn = connections[p];
      return oldConn.currentState->processEvent(socket, oldConn, ev); 
  }  
  
  notifyApp(app, TcpCode::NoConnExists, ev.id);
  return LocalCode::Success;
}

LocalCode abort(App* app, int socket, LocalPair lP, RemotePair rP){

  AbortEv ev;
  ConnPair p(lP,rP);
  if(connections.find(p) != connections.end()){
      Tcb& oldConn = connections[p];
      return oldConn.currentState->processEvent(socket, oldConn, ev); 
  }  
  
  notifyApp(app, TcpCode::NoConnExists, ev.id);
  return LocalCode::Success;
}

/*
open-
Models an open event call from an app to a kernel.
AppId is an id that the simulated app registers with the kernel, createdId is populated with the id of the connection.
createdId should only be used if LocalCode::Success is returned and there are no app notifications indicating the connection failed
*/
LocalCode open(App* app, int socket, bool passive, LocalPair lP, RemotePair rP, int& createdId){

  OpenEv ev;
  ev.passive = passive;
  
  Tcb newConn(app, lP, rP, passive);
  if(passive){
    newConn.currentState = make_shared<ListenS>();
  }
  else{
    //unspecified remote info in active open does not make sense
    if(rP.first == Unspecified || rP.second == Unspecified){
      notifyApp(app, TcpCode::ActiveUnspec, ev.id);
      return LocalCode::Success;
    }
    newConn.currentState = make_shared<SynSentS>();
  }
  
  if(lP.second == Unspecified){
    uint16_t chosenPort = pickDynPort();
    if(chosenPort != Unspecified){
      lP.second = chosenPort;
      newConn.lP = lP;
    }
    else{
      notifyApp(app, TcpCode::Resources, ev.id);
      return LocalCode::Success;
    }
  }
  if(lP.first == Unspecified){
    uint32_t chosenAddr = pickDynAddr(); 
    lP.first = chosenAddr;
    newConn.lP = lP;
  }
  
  ConnPair p(lP,rP);
  if(connections.find(p) != connections.end()){
    //duplicate connection
    Tcb& oldConn = connections[p];
    return oldConn.currentState->processEvent(socket, oldConn, ev); 
    
  }
  
  int id = 0;
  bool idWorked = pickId(id);
  if(idWorked) idMap[id] = p;
  else{
    notifyApp(app,TcpCode::Resources,ev.id);
    return LocalCode::Success;
  }
    
  //finally need to send initial syn packet in active open because state is set to synOpen
  if(!passive){
    pickRealIsn(newConn);
  
    bool ls = sendSyn(socket,newConn,newConn.lP,newConn.rP,false);
    if(ls){
      newConn.sUna = newConn.iss;
      newConn.sNxt = newConn.iss + 1;
      newConn.currentState = make_shared<SynSentS>();
    }
    else{
      reclaimId(id);
      return LocalCode::Socket;
    }

  }
  
  newConn.id = id;
  connections[p] = newConn;
  createdId = id;
  return LocalCode::Success;
  
}

