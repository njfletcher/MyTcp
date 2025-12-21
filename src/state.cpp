#include "driver.h"
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

State::State(){}
State::~State(){}

App::App(int ident, std::deque<TcpCode> aNotif, std::unordered_map<int, std::deque<TcpCode> > cNotifs): id(ident), appNotifs(aNotif), connNotifs(cNotifs) {}
int App::getId(){ return id; }
std::deque<TcpCode>& App::getAppNotifs(){ return appNotifs; }
std::unordered_map<int, std::deque<TcpCode> >& App::getConnNotifs(){ return connNotifs; }

Event::Event(uint32_t ident): id(ident){}
uint32_t Event::getId() { return id; }
OpenEv::OpenEv(bool p, uint32_t id): Event(id), passive(p){}
bool OpenEv::isPassive(){ return passive; }
SegmentEv::SegmentEv(IpPacket ipPacket, uint32_t id): Event(id), ipPacket(ipPacket){}
IpPacket& SegmentEv::getIpPacket(){ return ipPacket; }
SendEv::SendEv(std::deque<uint8_t> d, bool urg, bool psh, uint32_t id): Event(id), data(d), urgent(urg), push(psh){}
std::deque<uint8_t>& SendEv::getData(){ return data; }
bool SendEv::isUrgent(){ return urgent; }
bool SendEv::isPush(){ return push; }
ReceiveEv::ReceiveEv(uint32_t a, std::vector<uint8_t> buff, uint32_t id): Event(id), amount(a), providedBuffer(buff){}
uint32_t ReceiveEv::getAmount(){ return amount; }
std::vector<uint8_t>& ReceiveEv::getBuffer(){ return providedBuffer; }
CloseEv::CloseEv(uint32_t id): Event(id){}
AbortEv::AbortEv(uint32_t id): Event(id){}

Tcb::Tcb(App* parApp, LocalPair l, RemotePair r, bool passive) : parentApp(parApp), lP(l), rP(r), passiveOpen(passive){}
Tcb::Tcb(App* parApp, LocalPair l, RemotePair r, bool passive, int ident) : parentApp(parApp), lP(l), rP(r), passiveOpen(passive), id(ident){}

LocalCode Tcb::processEventEntry(int socket, OpenEv& oe){ return currentState->processEvent(socket, *this, oe); }
LocalCode Tcb::processEventEntry(int socket, SegmentEv& se, RemoteCode& remCode){ return currentState->processEvent(socket, *this, se, remCode); }
LocalCode Tcb::processEventEntry(int socket, SendEv& se){ return currentState->processEvent(socket, *this, se); }
LocalCode Tcb::processEventEntry(int socket, ReceiveEv& re){ return currentState->processEvent(socket, *this, re); }
LocalCode Tcb::processEventEntry(int socket, CloseEv& ce){ return currentState->processEvent(socket, *this, ce); }
LocalCode Tcb::processEventEntry(int socket, AbortEv& ae){ return currentState->processEvent(socket, *this, ae); }

App* Tcb::getParApp() { return parentApp; }
int Tcb::getId(){ return id; }
ConnPair Tcb::getConnPair(){ return ConnPair(lP,rP); }

State* Tcb::getCurrentState(){return &*currentState;}

void Tcb::setCurrentState(std::unique_ptr<State> s){ currentState = std::move(s); }

bool Tcb::getPushSeen(){ return pushSeen;}
bool Tcb::getUrgentSignaled(){ return urgentSignaled;}

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

bool Tcb::timeWaitTimerExpired(){
  if(timeWaitTimerExpire == std::chrono::steady_clock::time_point::min()) return false;
  return std::chrono::steady_clock::now() >= timeWaitTimerExpire;
}
void Tcb::startTimeWaitTimer(){
  timeWaitTimerExpire = std::chrono::steady_clock::now() + timeWaitInterval;
}

StateNums ListenS::getNum(){ return StateNums::LISTEN; }
StateNums SynSentS::getNum(){ return StateNums::SYNSENT; }
StateNums SynRecS::getNum(){ return StateNums::SYNREC; }
StateNums EstabS::getNum(){ return StateNums::ESTAB; }
StateNums FinWait1S::getNum(){ return StateNums::FINWAIT1; }
StateNums FinWait2S::getNum(){ return StateNums::FINWAIT2; }
StateNums CloseWaitS::getNum(){ return StateNums::CLOSEWAIT; }
StateNums ClosingS::getNum(){ return StateNums::CLOSING; }
StateNums LastAckS::getNum(){ return StateNums::LASTACK; }
StateNums TimeWaitS::getNum(){ return StateNums::TIMEWAIT; }

void cleanup(int res, EVP_MD* sha256, EVP_MD_CTX* ctx, unsigned char * outdigest){

  OPENSSL_free(outdigest);
  EVP_MD_free(sha256);
  EVP_MD_CTX_free(ctx);
  
  if(res < 0){
    ERR_print_errors_fp(stderr);
  }
}

//effective send mss: how much tcp data are we actually allowed to send to the peer.
uint32_t Tcb::getEffectiveSendMss(vector<TcpOption> optionList){

  uint32_t optionListByteCount = 0;
  for(auto i = optionList.begin(); i < optionList.end(); i++){
    TcpOption o = *i;
    optionListByteCount++; //kind byte
    if(o.getHasLength()){
      optionListByteCount++;
    }
    optionListByteCount += o.getData().size();
    
  }
  uint32_t messageSize = peerMss + TCP_MIN_HEADER_LEN;
  uint32_t mmsS = getMmsS();
  if(mmsS < messageSize) messageSize = mmsS;
  
  return messageSize - optionListByteCount - TCP_MIN_HEADER_LEN; //ipOptionByteCount is not considered because we are not setting any ip options on the raw socket.
}

//assumes numBytes does not exceed usableWindow
LocalCode Tcb::packageAndSendSegments(int socket, uint32_t usableWindow, uint32_t numBytes){

  bool piggybackFin = false;
  if(!closeQueue.empty() && (sendQueueByteCount <= numBytes) && (usableWindow > numBytes)) piggybackFin = true;

  TcpPacket sendPacket;
  while(true){
  
     SendEv& ev = sendQueue.front();
      
     //cant append urgent data after non urgent data: the urgent pointer will claim all the data is urgent when it is not
     if(ev.isUrgent() && (!sendPacket.getFlag(TcpPacketFlags::URG) && (sendPacket.getPayload().size() > 0))){
          bool ls = sendDataPacket(socket,sendPacket);
          if(!ls){
              return LocalCode::SOCKET;
          }
          sendPacket = TcpPacket{};
          sendPacket.setSeq(sNxt);
     }
     
     while((ev.getData().size() > 0) && (numBytes > 0)){
        sendPacket.getPayload().push_back(ev.getData().front());
        ev.getData().pop_front();
        sNxt++;
        sendQueueByteCount--;
        numBytes--;
     }
     
     if(ev.isUrgent()){
        sendPacket.setFlag(TcpPacketFlags::URG);
        sendPacket.setUrgentPointer(sNxt - sendPacket.getSeqNum() -1);
     }
     
     if(ev.getData().size() == 0){
        sendQueue.pop_front();
        if(ev.isPush()){
          sendPacket.setFlag(TcpPacketFlags::PSH);
        }
     }
    
     if(numBytes == 0){
        if(piggybackFin){
          sendPacket.setFlag(TcpPacketFlags::FIN);
          sNxt++;
        }
        bool ls = sendDataPacket(socket,sendPacket); 
        if(!ls){
          return LocalCode::SOCKET;
        }  
        return LocalCode::SUCCESS;
     }
      
  }
  
  return LocalCode::SUCCESS;

}

bool Tcb::scanForPush(uint32_t usableWindow, int& bytes){
    
    int bytesCovered;
    for(auto iter = sendQueue.begin(); iter < sendQueue.end(); iter++){
      SendEv& ev = *iter;
      bytesCovered+= ev.getData().size();
      if(bytesCovered > usableWindow){
        return false;
      }
      if(ev.isPush()){
        bytes = bytesCovered;
        return true;
      }
      
    }
    return false;
}

LocalCode Tcb::trySend(int socket){

  //sends should only be processed at or after establishment of the connection
  if(currentState->getNum() < StateNums::ESTAB){
    return LocalCode::SUCCESS;
  }

  while(true){
    uint32_t effSendMss = getEffectiveSendMss(vector<TcpOption>{});
    uint32_t usableWindow = sUna + sWnd - sNxt; 
    uint32_t minDu = usableWindow;
    if(sendQueueByteCount < minDu) minDu = sendQueueByteCount;
    if(minDu < 1){
      break;
    }
    bool nagleCheck = (((sNxt == sUna) && nagle) || !nagle);
    int endPush = 0;
  
    if(minDu >= effSendMss){
      LocalCode lc = packageAndSendSegments(socket, usableWindow, effSendMss);
      stopSwsTimer();
      if(lc != LocalCode::SUCCESS) return lc;
    }
    else if(nagleCheck && scanForPush(usableWindow,endPush)){
      LocalCode lc = packageAndSendSegments(socket, usableWindow, endPush);
      stopSwsTimer();
      if(lc != LocalCode::SUCCESS) return lc;
    }
    else if(nagleCheck && (minDu >= (static_cast<uint32_t>(MAX_WINDOW_SWS_SEND_FRACT * maxSWnd)))){
      LocalCode lc = packageAndSendSegments(socket, usableWindow, minDu);
      stopSwsTimer();
      if(lc != LocalCode::SUCCESS) return lc;
    }
    else if(swsTimerExpired()){
      LocalCode lc = packageAndSendSegments(socket, usableWindow, minDu);
      stopSwsTimer();
      if(lc != LocalCode::SUCCESS) return lc;
    }
    else{
      //only want to set the timer if its stopped, its possible the timer is already set from a previous failure to send
      if(swsTimerStopped()){
        resetSwsTimer();
      }
      break;
      
    }
    
  }
  
  return LocalCode::SUCCESS;
  
}

bool Tcb::pickRealIsn(){

  chrono::time_point t = chrono::system_clock::now();
  chrono::duration d = t.time_since_epoch();
  uint32_t tVal = d.count();

  unsigned char randBuffer[KEY_LEN];
  if(RAND_bytes(randBuffer, KEY_LEN) < 1){
    ERR_print_errors_fp(stderr);
    return false;
  }
  
  unsigned char buffer[KEY_LEN + (sizeof(rP.first) * 2) + (sizeof(rP.second) * 2)];
  
  size_t i = 0;
  size_t end = sizeof(rP.first);
  for(;i < end; i++){
    size_t shift = ((sizeof(rP.first) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (rP.first & (val << shift)) >> shift;
  }
  end = end + sizeof(lP.first);
  for(; i < end; i++){
    size_t shift = ((sizeof(lP.first) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (lP.first & (val << shift)) >> shift;
  }
  end = end + sizeof(rP.second);
  for(; i < end; i++){
    size_t shift = ((sizeof(rP.second) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (rP.second & (val << shift)) >> shift;
  }
  end = end + sizeof(lP.second);
  for(; i < end; i++){
    size_t shift = ((sizeof(lP.second) -1) * 8) - (8 * i);
    uint32_t val = 0xff;
    buffer[i] = (lP.second & (val << shift)) >> shift;
  }

  for(size_t j = 0; j < KEY_LEN; j++){
    buffer[i+j] = randBuffer[j];
  }
  
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if(ctx == NULL){
    cleanup(-1,NULL,ctx,NULL);
    return false;
  }
  
  EVP_MD* sha256 = EVP_MD_fetch(NULL,"SHA256", NULL);
  if(!EVP_DigestInit_ex(ctx,sha256,NULL)){
    cleanup(-1,sha256,ctx,NULL);
    return false;
  }
  
  if( !EVP_DigestUpdate(ctx, buffer, sizeof(buffer))){
    cleanup(-1,sha256,ctx,NULL);
    return false;
  }
  
  unsigned char* outdigest = (unsigned char*) OPENSSL_malloc(EVP_MD_get_size(sha256));
  if(outdigest == NULL){
    cleanup(-1, sha256,ctx,outdigest);
    return false;
  }
  
  unsigned int len = 0;
  if(!EVP_DigestFinal_ex(ctx, outdigest, &len)){
    cleanup(-1,sha256,ctx,outdigest);
    return false;
  }
  
  cleanup(0,sha256,ctx,outdigest);
  
  if(len < 4){
    return false;
  }
  
  uint32_t bufferTrunc = outdigest[0] | (outdigest[1] << 8) | (outdigest[2] << 16) | (outdigest[3] << 24);
  
  iss = tVal + bufferTrunc;
  return true;
}

//TODO: research tcp security/compartment and how this check should work
bool Tcb::checkSecurity(IpPacket& p){
  return true;
}

//MSS: maximum tcp segment(data only) size.
uint32_t getMSSValue(uint32_t destAddr){
  uint32_t maxMss = getMmsR() - TCP_MIN_HEADER_LEN;
  uint32_t calcMss = getMtu(destAddr) - IP_MIN_HEADER_LEN - TCP_MIN_HEADER_LEN;
  if(calcMss > maxMss) return maxMss;
  else return calcMss;
}

/*verifyRecWindow-
returns true if the seqnum from the peer packet falls in our current window, false if not
*/
bool Tcb::verifyRecWindow(TcpPacket& p){

  uint32_t segLen = p.getSegSize();
  uint32_t seqNum = p.getSeqNum();
  
  if(segLen > 0){
    if(rWnd >0){
      uint32_t lastByte = seqNum + segLen - 1;
      return ((rNxt <= seqNum && seqNum < (rNxt + rWnd)) || (rNxt <= lastByte && lastByte < (rNxt + rWnd)));
    }
    else return false;
  
  }
  else{
    if(rWnd > 0){
      return (rNxt <= seqNum && seqNum < + (rWnd + rNxt));
    }
    else{
      return (seqNum == rNxt);
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

bool Tcb::sendReset(int socket, LocalPair lp, RemotePair rp, uint32_t ackNum, bool ackFlag, uint32_t seqNum){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  if(ackFlag){
    sPacket.setFlag(TcpPacketFlags::ACK);
  }
  sPacket.setFlag(TcpPacketFlags::RST).setSrcPort(lp.second).setDestPort(rp.second).setSeq(seqNum).setAck(ackNum).setOptions(options).setPayload(data).setRealChecksum(lp.first, rp.first);
      
  return sendPacket(socket, rp.first, sPacket);
  
}

//assumes seq num, data, urgPointer and urgFlag have already been set
bool Tcb::sendDataPacket(int socket, TcpPacket& p){

 p.setFlag(TcpPacketFlags::ACK).setSrcPort(lP.second).setDestPort(rP.second).setAck(rNxt).setWindow(rWnd).setOptions(vector<TcpOption>{}).setRealChecksum(lP.first, rP.first);
      
  return sendPacket(socket,rP.first,p);
}

bool Tcb::sendCurrentAck(int socket){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  sPacket.setFlag(TcpPacketFlags::ACK).setSrcPort(lP.second).setDestPort(rP.second).setSeq(sNxt).setAck(rNxt).setWindow(rWnd).setOptions(options).setPayload(data).setRealChecksum(lP.first, rP.first);
      
  return sendPacket(socket,rP.first,sPacket);
}

bool Tcb::sendFin(int socket){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  sPacket.setFlag(TcpPacketFlags::FIN).setFlag(TcpPacketFlags::ACK).setSrcPort(lP.second).setDestPort(rP.second).setSeq(sNxt).setAck(rNxt).setWindow(rWnd).setOptions(options).setPayload(data).setRealChecksum(lP.first, rP.first);
      
  return sendPacket(socket,rP.first,sPacket);
  
}

bool Tcb::sendSyn(int socket, LocalPair lp, RemotePair rp, bool sendAck){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
     
  if(sendAck){
    sPacket.setFlag(TcpPacketFlags::ACK);
    sPacket.setAck(rNxt);
  }
  sPacket.setFlag(TcpPacketFlags::SYN).setSrcPort(lp.second).setDestPort(rp.second).setSeq(iss).setWindow(rWnd).setOptions(options).setPayload(data);
    
  if(myMss != DEFAULT_MSS){
    vector<uint8_t> mss;
    loadBytes<uint16_t>(toAltOrder<uint16_t>(myMss),mss);
    TcpOption mssOpt(static_cast<uint8_t>(TcpOptionKind::MSS), 0x4, true, mss);
    sPacket.getOptions().push_back(mssOpt);
    sPacket.setDataOffset(sPacket.getDataOffset() + 1); //since the mss option is 4 bytes we can cleanly add one word to offset.
  }
  
  sPacket.setRealChecksum(lp.first, rp.first);  
  return sendPacket(socket, rp.first, sPacket);
  
}

void Tcb::initSenderState(bool flipOpenType){
      sUna = iss;
      sNxt =  iss + 1;
      if(flipOpenType) passiveOpen = !passiveOpen;
}

LocalCode ListenS::processEvent(int socket, Tcb& b, OpenEv& oe){

  bool passive = oe.isPassive();
  if(!passive){
  
    //no need to check for active unspec again, outer open call already does it
    b.pickRealIsn();
    
    ConnPair cp = b.getConnPair();
    bool ls = b.sendSyn(socket, cp.first, cp.second, false);
    if(ls){
      b.initSenderState(true);
      b.setCurrentState(make_unique<SynSentS>());
      return LocalCode::SUCCESS;
    }
    else return LocalCode::SOCKET;
    
  }
  else{
    notifyApp(b.getParApp(), b.getId(), TcpCode::DUPCONN, oe.getId());
    return LocalCode::SUCCESS;
  }
  
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode SynRecS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode EstabS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode FinWait1S::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode FinWait2S::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode CloseWaitS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode ClosingS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode LastAckS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode TimeWaitS::processEvent(int socket, Tcb& b, OpenEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::DUPCONN, oe.getId());
  return LocalCode::SUCCESS;
}


void Tcb::checkAndSetPeerMSS(TcpPacket& tcpP){

  vector<TcpOption>& options = tcpP.getOptions();
  for(auto i = options.begin(); i < options.end(); i++){
  
    TcpOption o = *i;
    if(o.getKind() == static_cast<uint8_t>(TcpOptionKind::MSS)){
    
      uint16_t sentMss = toAltOrder<uint16_t>(unloadBytes<uint16_t>(o.getData().data(),0));
      peerMss = sentMss;
      break;
    }
  }

}

void Tcb::initReceiverState(uint32_t seqNum){   
    irs = seqNum;
    appNewData = irs;
    rNxt = irs + 1;
}

void Tcb::specifyRemotePair(RemotePair recPair){
    rP = recPair;
}

LocalCode ListenS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();
  RemotePair recPair(ipP.getSrcAddr(), tcpP.getSrcPort());
    
  //if im in the listen state, I havent sent anything, so rst could not be referring to anything valid.
  if(tcpP.getFlag(TcpPacketFlags::RST)){
    remCode = RemoteCode::UNEXPECTEDPACKET;
    return LocalCode::SUCCESS;
  }
  
  ConnPair cp = b.getConnPair();
  //if im in the listen state, I havent sent anything. so any ack at all is an unacceptable ack
  if(tcpP.getFlag(TcpPacketFlags::ACK)){
    bool sent = b.sendReset(socket, cp.first, recPair, 0, false, tcpP.getAckNum());
    remCode = RemoteCode::UNEXPECTEDPACKET;
    if(!sent) return LocalCode::SOCKET;
    else return LocalCode::SUCCESS;
  }
  
  if(tcpP.getFlag(TcpPacketFlags::SYN)){
  
    uint32_t segLen = tcpP.getSegSize();
    if(!b.checkSecurity(ipP)){
      bool sent = b.sendReset(socket, cp.first, recPair, tcpP.getSeqNum() + segLen , true, 0);
      remCode = RemoteCode::MALFORMEDPACKET;
      if(!sent) return LocalCode::SOCKET;
      else return LocalCode::SUCCESS;
    }
    
    b.checkAndSetPeerMSS(tcpP);
    b.pickRealIsn();
    b.initReceiverState(tcpP.getSeqNum());
      
    bool sent = b.sendSyn(socket, cp.first, recPair, true);
    if(sent){
      b.initSenderState(false);
      b.setCurrentState(make_unique<SynRecS>());
      b.specifyRemotePair(recPair);
      
      //TODO 3.10.7.2 possibly trigger another event for processing of data and other control flags here: maybe forward packet without syn and ack flags set?
      remCode = RemoteCode::SUCCESS;
      return LocalCode::SUCCESS;
    }
    return LocalCode::SOCKET;
    
  }
  else{
    remCode = RemoteCode::UNEXPECTEDPACKET;
    return LocalCode::SUCCESS;
  }

}

bool Tcb::checkUnacceptableAck(uint32_t ackNum){
  return (ackNum <= sUna || ackNum > sNxt);
}

bool Tcb::checkBlindResetPossible(uint32_t seqNum){
  return (seqNum != rNxt);
}

void Tcb::advanceUna(uint32_t ackNum){
  sUna = ackNum;
}

void Tcb::updateWindowVars(uint32_t wind, uint32_t seqNum, uint32_t ackNum,bool ack){
      sWnd = wind;
      if(sWnd >= maxSWnd) maxSWnd = sWnd;
      sWl1 = seqNum;
      if(ack) sWl2 = ackNum;
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();
  uint8_t ackFlag = tcpP.getFlag(TcpPacketFlags::ACK);
  
  ConnPair cp = b.getConnPair();
  uint32_t ackN = tcpP.getAckNum();
  if(ackFlag){ 
    if(b.checkUnacceptableAck(ackN)){
      remCode = RemoteCode::UNEXPECTEDPACKET;
      if(!tcpP.getFlag(TcpPacketFlags::RST)){
        bool sent = b.sendReset(socket, cp.first, cp.second, 0, false, ackN);
        if(!sent) return LocalCode::SOCKET;
        else return LocalCode::SUCCESS;
      }
      else return LocalCode::SUCCESS;
    }
  }
    
  uint32_t seqN = tcpP.getSeqNum();
  if(tcpP.getFlag(TcpPacketFlags::RST)){
    //RFC 5961, preventing blind reset attack. 
    if(b.checkBlindResetPossible(seqN)){
      remCode = RemoteCode::UNEXPECTEDPACKET;
      return LocalCode::SUCCESS;
    }
    
    if(ackFlag){
      removeConn(b);
      notifyApp(b.getParApp(), b.getId(),TcpCode::CONNRST, se.getId());
    }
    else{
      remCode = RemoteCode::UNEXPECTEDPACKET;
    }
    
    return LocalCode::SUCCESS;
  }
  
  if(!b.checkSecurity(ipP)){
    bool sent = false;
    if(tcpP.getFlag(TcpPacketFlags::ACK)){
      sent = b.sendReset(socket, cp.first, cp.second, 0, false, ackN);
    }
    else{
      sent = b.sendReset(socket, cp.first, cp.second, seqN + tcpP.getSegSize(),true,0);
    }
    remCode = RemoteCode::MALFORMEDPACKET;
    if(!sent) return LocalCode::SOCKET;
    else return LocalCode::SUCCESS;
  }
  
  if(tcpP.getFlag(TcpPacketFlags::SYN)){
      
    b.initReceiverState(seqN);   
    b.checkAndSetPeerMSS(tcpP);
  
    if(tcpP.getFlag(TcpPacketFlags::ACK)){
      //standard connection attempt
      
      b.advanceUna(ackN);// ack already validated earlier in method
      b.updateWindowVars(tcpP.getWindow(),seqN,ackN,true);
      
      //TODO: remove segments that are acked from retransmission queue.
      //TODO: data or controls that were queued for transmission may be added to this packet
      bool sent = b.sendCurrentAck(socket);
      if(sent){
          b.setCurrentState(make_unique<EstabS>());
          return LocalCode::SUCCESS;
      }
      else{
        return LocalCode::SOCKET;
      }
    
    }
    else{
      
      b.updateWindowVars(tcpP.getWindow(),seqN,ackN,false);
      //simultaneous connection attempt
      bool sent = b.sendSyn(socket, cp.first, cp.second, true);
      if(sent){
        b.setCurrentState(make_unique<SynRecS>());
        return LocalCode::SUCCESS;
      }
      else{
        return LocalCode::SOCKET;
      }
    }
    
  }
  //need at least a syn or a rst
  else{
    remCode = RemoteCode::UNEXPECTEDPACKET;
    return LocalCode::SUCCESS;
  }
  
}

LocalCode Tcb::checkSequenceNum(int socket, TcpPacket& tcpP, RemoteCode& remCode){

  if(!verifyRecWindow(tcpP)){
    remCode = RemoteCode::UNEXPECTEDPACKET;
    if(!tcpP.getFlag(TcpPacketFlags::RST)){
      bool sent = sendCurrentAck(socket);
      if(!sent) return LocalCode::SOCKET;
      else return LocalCode::SUCCESS;
    }
    return LocalCode::SUCCESS;
  }
  
  return LocalCode::SUCCESS;
}

/*Status checkSaveForLater(Tcb&b, IpPacket& ipP){

  uint32_t seqNum = tcpP.getSeqNum();
  //SHLD 31 packet in window but not the expected one should be held for later processing.
  if(seqNum > b.rNxt){
    b.waitingPackets[seqNum] = ipP;
    return Status();
  }

}*/

LocalCode Tcb::checkReset(int socket, TcpPacket& tcpP, bool windowChecked, RemoteCode& remCode, bool& reset){

  if(tcpP.getFlag(TcpPacketFlags::RST)){
  
      //check for RFC 5961S3 rst attack mitigation. 
      if(!windowChecked && !verifyRecWindow(tcpP)){
        remCode = RemoteCode::UNEXPECTEDPACKET;
        return LocalCode::SUCCESS;
      }
      
      if(tcpP.getSeqNum() != rNxt){  
        bool sent = sendCurrentAck(socket);
        remCode = RemoteCode::UNEXPECTEDPACKET;
        if(!sent) return LocalCode::SOCKET;
        else return LocalCode::SUCCESS;
      }
      
      reset = true;
  }
  
  return LocalCode::SUCCESS;

}

LocalCode Tcb::checkSec(int socket, IpPacket& ipP, RemoteCode& remCode){
  
  TcpPacket& tcpP = ipP.getTcpPacket();

  if(!checkSecurity(ipP)){
    bool sent = false;
    if(tcpP.getFlag(TcpPacketFlags::ACK)){
      sent = sendReset(socket, lP, rP, 0, false, tcpP.getAckNum());
    }
    else{
      sent = sendReset(socket, lP, rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    
    remCode = RemoteCode::MALFORMEDPACKET;
    if(!sent) return LocalCode::SOCKET;
    
  }
  return LocalCode::SUCCESS;

}

LocalCode Tcb::checkSyn(int socket, TcpPacket& tcpP, RemoteCode& remCode){

  if(tcpP.getFlag(TcpPacketFlags::SYN)){
  
    //challenge ack recommended by RFC 5961  
    bool sent = sendCurrentAck(socket);
    remCode = RemoteCode::UNEXPECTEDPACKET;
    if(!sent) return LocalCode::SOCKET;
    else return LocalCode::SUCCESS;
  }
  return LocalCode::SUCCESS;
  
}

LocalCode Tcb::checkAck(int socket, TcpPacket& tcpP, RemoteCode& remCode){
  
  if(tcpP.getFlag(TcpPacketFlags::ACK)){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (sUna - maxSWnd)) && (ackNum <= sNxt))){
        
      bool sent = sendCurrentAck(socket);
      remCode = RemoteCode::UNEXPECTEDPACKET;
      if(!sent) return LocalCode::SOCKET;
      else return LocalCode::SUCCESS;
    }
    
    return LocalCode::SUCCESS;
  }
  else{
    remCode = RemoteCode::UNEXPECTEDPACKET;
    return LocalCode::SUCCESS;
  }
  
}

LocalCode Tcb::establishedAckLogic(int socket, TcpPacket& tcpP, RemoteCode& remCode){

    uint32_t ackNum = tcpP.getAckNum();
    uint32_t seqNum = tcpP.getSeqNum();
    
    if((ackNum >= sUna) && (ackNum <= sNxt)){
    
      if(ackNum > sUna){
        sUna = ackNum;
        //TODO: remove acked segments from retransmission queue
        //respond ok to buffers for app
      }
      
      if((sWl1 < seqNum) || ((sWl1 == seqNum) && (sWl2 <= ackNum))){
        sWnd = tcpP.getWindow();
        if(sWnd >= maxSWnd) maxSWnd = sWnd;
        sWl1 = seqNum;
        sWl2 = ackNum;
      }
      return LocalCode::SUCCESS;
            
    }
    else{
      remCode = RemoteCode::UNEXPECTEDPACKET;
      if(ackNum > sNxt){
            bool sent = sendCurrentAck(socket);
            if(!sent) return LocalCode::SOCKET;
            else return LocalCode::SUCCESS;
      }
      return LocalCode::SUCCESS;
    }    
    
}

LocalCode Tcb::checkUrg(TcpPacket& tcpP, Event& e){

  if(tcpP.getFlag(TcpPacketFlags::URG)){
    uint32_t segUp = tcpP.getSeqNum() + tcpP.getUrg();
    if(rUp < segUp) rUp = segUp;
    if((rUp >= appNewData) && !urgentSignaled){
      notifyApp(parentApp, id, TcpCode::URGENTDATA, e.getId());
      urgentSignaled = true;
    }
  }
  return LocalCode::SUCCESS;
}


void Tcb::updateWindowSWSRec(uint32_t freshRecDataAmount){
  
  uint32_t reduction = ARRANGED_SEGMENTS_BYTES_MAX - arrangedSegmentsByteCount - rWnd;
  if(reduction >= min(static_cast<uint32_t>(MAX_BUFFER_SWS_REC_FRACT * ARRANGED_SEGMENTS_BYTES_MAX), getEffectiveSendMss({}))){
    rWnd = ARRANGED_SEGMENTS_BYTES_MAX - arrangedSegmentsByteCount;
  }
  else{
    //sws rec algorithm says to keep right edge(rNxt + rWnd) fixed while the above condition is not met. In other words, reduce the advertised window as rNxt increases
    rWnd -= freshRecDataAmount;
  }

}

LocalCode Tcb::processData(TcpPacket& tcpP){

  uint32_t seqNum = tcpP.getSeqNum();
  //at this point segment is in the window and any segment with seqNum > rNxt has been put aside for later processing.
  //This leaves two cases: either seqNum < rNxt but there is unprocessed data in the window or seqNum == rNxt
  //regardless want to start reading data at the first unprocessed byte and not reread already processed data.
   
  
  if(arrangedSegments.empty() || (seqNum != arrangedSegments.back().getSeqNum())){
    TcpSegmentSlice newSlice(tcpP.getFlag(TcpPacketFlags::PSH), seqNum, {});
    arrangedSegments.push_back(newSlice);
  }
  
  uint32_t beginUnProc = static_cast<uint32_t>(rNxt - seqNum); //CHECK THIS
  uint32_t index = beginUnProc;
  while((arrangedSegmentsByteCount < ARRANGED_SEGMENTS_BYTES_MAX) && (index < static_cast<uint32_t>(tcpP.getPayload().size()))){
    arrangedSegments.back().getData().push(tcpP.getPayload()[index]);
    index++;
    arrangedSegmentsByteCount++;
    rNxt++;
  }
  
  updateWindowSWSRec((index - beginUnProc));
   
  return LocalCode::SUCCESS;
}

LocalCode Tcb::checkFin(int socket, TcpPacket& tcpP, bool& fin, Event& e){
  
  //can only process fin if we didnt fill up the buffer with processing data and have a non zero window left.
  if(rWnd > 0){
    if(tcpP.getFlag(TcpPacketFlags::FIN)){
      rNxt = rNxt + 1;
      //TODO: return conn closing to any pending recs and push any waiting segments.
      notifyApp(parentApp, id, TcpCode::CONNCLOSING, e.getId());
      fin = true;
    }
  }
  return LocalCode::SUCCESS;
}


bool Tcb::wasPassiveOpen(){ return passiveOpen; }

LocalCode SynRecS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){
 
  LocalCode s;
  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();
  
  s = b.checkSequenceNum(socket, tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
    
  bool reset = false;
  s = b.checkReset(socket, tcpP,true, remCode, reset);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(reset){
    if(b.wasPassiveOpen()){
      b.setCurrentState(make_unique<ListenS>());
      return LocalCode::SUCCESS;
    }
    else{
      removeConn(b);
      notifyApp(b.getParApp(), b.getId(), TcpCode::CONNREF, se.getId());
      return LocalCode::SUCCESS;
    }
    //TODO : flush retransmission queue
  }
  
  s = b.checkSec(socket,ipP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;

  if(tcpP.getFlag(TcpPacketFlags::SYN)){
  
    if(b.wasPassiveOpen()){
      b.setCurrentState(make_unique<ListenS>());
      return LocalCode::SUCCESS;
    }
    //challenge ack recommended by RFC 5961  
    bool sent = b.sendCurrentAck(socket);
    remCode = RemoteCode::UNEXPECTEDPACKET;
    if(!sent) return LocalCode::SOCKET;
    else return LocalCode::SUCCESS;
    
  }
    
  ConnPair cp = b.getConnPair();
  s = b.checkAck(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  uint32_t ackNum = tcpP.getAckNum();
  if(!b.checkUnacceptableAck(ackNum)){
  
    b.setCurrentState(make_unique<EstabS>());
    b.updateWindowVars(tcpP.getWindow(), tcpP.getSeqNum(), ackNum, true);
    //TODO trigger further processing event
    return LocalCode::SUCCESS;
    
  }
  else{
    bool sent = b.sendReset(socket, cp.first, cp.second, 0, false, ackNum);
    remCode = RemoteCode::UNEXPECTEDPACKET;
    if(!sent) return LocalCode::SOCKET;
    else return LocalCode::SUCCESS;
  }
  
  //anything past this that needs processing will have been handed off to synchronized state
  
}

LocalCode EstabS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();

  s = b.checkSequenceNum(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  
  bool reset = false;
  s = b.checkReset(socket,tcpP,true, remCode, reset);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(reset){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
  }
  
  s = b.checkSec(socket,ipP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  
  if(remCode != RemoteCode::SUCCESS){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
    else return LocalCode::SUCCESS;
  }
  
  s = b.checkSyn(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;

  s = b.checkAck(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.establishedAckLogic(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.checkUrg(tcpP,se);
  if(s != LocalCode::SUCCESS) return s;
  
  s = b.processData(tcpP);  
  if(s != LocalCode::SUCCESS) return s;
  
  bool fin = false;
  s = b.checkFin(socket,tcpP,fin,se);
  if(s != LocalCode::SUCCESS) return s;
  
  if(fin){
      b.setCurrentState(make_unique<CloseWaitS>());
      return LocalCode::SUCCESS;
  }
  
  bool sent = b.sendCurrentAck(socket);
  if(!sent) return LocalCode::SOCKET;
  else return LocalCode::SUCCESS;
  
}

bool Tcb::checkFinFullyAcknowledged(uint32_t ackNum){
  return (ackNum == sNxt);
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();

  s = b.checkSequenceNum(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  bool reset = false;
  s = b.checkReset(socket,tcpP,true, remCode, reset);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(reset){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
  }
  
  s = b.checkSec(socket, ipP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  
  if(remCode != RemoteCode::SUCCESS){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
    return LocalCode::SUCCESS;
  }
  
  s = b.checkSyn(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.checkAck(socket,tcpP,remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.establishedAckLogic(socket, tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  // if we've reached this part we know ack is set and acceptable
  bool finAcked = b.checkFinFullyAcknowledged(tcpP.getAckNum());
  if(finAcked){
      b.setCurrentState(make_unique<FinWait2S>());
      //spec says to further process(urg,data,fin,etc) in finWait2
      //these steps are the same for finWait1 and finWait2(with a minor check needed for rec fin + ack fin later in this logic)
      //so fall through
  }
  
  s = b.checkUrg(tcpP, se);
  if(s != LocalCode::SUCCESS) return s;
  
  s = b.processData(tcpP);
  if(s != LocalCode::SUCCESS) return s;
  
  
  bool fin = false;
  s = b.checkFin(socket,tcpP,fin,se);
  if(s != LocalCode::SUCCESS) return s;
  
  if(fin){
      if(finAcked){
        b.setCurrentState(make_unique<TimeWaitS>());
        b.startTimeWaitTimer();
      }
      else{
        b.setCurrentState(make_unique<ClosingS>());
      }
      return LocalCode::SUCCESS;
  }
        
  bool sent = b.sendCurrentAck(socket);
  if(!sent) return LocalCode::SOCKET;
  else return LocalCode::SUCCESS;
  
}

bool Tcb::checkRespondToUserClose(){
  return (retransmit.size() < 1);
}

LocalCode FinWait2S::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;  
  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();

  s = b.checkSequenceNum(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  bool reset = false;
  s = b.checkReset(socket,tcpP,true,remCode, reset);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(reset){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
  }
  
  s = b.checkSec(socket,ipP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  
  if(remCode != RemoteCode::SUCCESS){  
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
    return LocalCode::SUCCESS;
  }
  
  s = b.checkSyn(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.checkAck(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.establishedAckLogic(socket, tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(b.checkRespondToUserClose()){
      notifyApp(b.getParApp(), b.getId(), TcpCode::OK, se.getId());
  }
  
  s = b.checkUrg(tcpP, se);
  if(s != LocalCode::SUCCESS) return s;
  
  s = b.processData(tcpP);
  if(s != LocalCode::SUCCESS) return s;
  
  bool fin = false;
  s = b.checkFin(socket,tcpP,fin,se);
  if(s != LocalCode::SUCCESS) return s;
  
  if(fin){
      b.setCurrentState(make_unique<TimeWaitS>());
      b.startTimeWaitTimer();
      return LocalCode::SUCCESS;
  }
        
  bool sent = b.sendCurrentAck(socket);
  if(!sent) return LocalCode::SOCKET;
  else return LocalCode::SUCCESS;
  
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();

  s = b.checkSequenceNum(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  bool reset = false;
  s = b.checkReset(socket,tcpP,true, remCode, reset);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(reset){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
  }
  
  s = b.checkSec(socket,ipP,remCode);
  if(s != LocalCode::SUCCESS) return s;
  
  if(remCode != RemoteCode::SUCCESS){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
    return LocalCode::SUCCESS;
  }
  
  s = b.checkSyn(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.checkAck(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.establishedAckLogic(socket, tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  remCode = RemoteCode::UNEXPECTEDPACKET;
  return LocalCode::SUCCESS;
}

LocalCode ClosingS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();

  s = b.checkSequenceNum(socket,tcpP,remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;

  bool reset = false;
  s = b.checkReset(socket,tcpP,true, remCode, reset);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(reset){
    LocalCode c = remConnOnly(socket, b);
    if(c != LocalCode::SUCCESS) return c;
  }
  
  s = b.checkSec(socket,ipP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  
  if(remCode != RemoteCode::SUCCESS){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
    return LocalCode::SUCCESS;
  }
  
  s = b.checkSyn(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.checkAck(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.establishedAckLogic(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  // if we've reached this part we know ack is set and acceptable
  if(b.checkFinFullyAcknowledged(tcpP.getAckNum())){
      //fin segment fully acknowledged
      b.setCurrentState(make_unique<TimeWaitS>());
      b.startTimeWaitTimer();
      return LocalCode::SUCCESS;
  }
    
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  remCode = RemoteCode::UNEXPECTEDPACKET;
  return LocalCode::SUCCESS;
}

LocalCode LastAckS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();
  
  s = b.checkSequenceNum(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  //s = checkSaveForLater(b,ipP);
  //if(s != LocalCode::Success) return s;
  
  bool reset = false;
  s = b.checkReset(socket,tcpP,true,remCode, reset);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(reset){
    LocalCode c = remConnOnly(socket, b);
    if(c != LocalCode::SUCCESS) return c;
  }
  
  s = b.checkSec(socket,ipP,remCode);
  if(s != LocalCode::SUCCESS) return s;
  
  if(remCode != RemoteCode::SUCCESS){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
    return LocalCode::SUCCESS;
  }
  
  s = b.checkSyn(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  

  s = b.checkAck(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(b.checkFinFullyAcknowledged(tcpP.getAckNum())){
    removeConn(b);
    return LocalCode::SUCCESS;
  }
  else{
    remCode = RemoteCode::UNEXPECTEDPACKET;
    return LocalCode::SUCCESS;
  }
  
  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  remCode =  RemoteCode::UNEXPECTEDPACKET;
  return LocalCode::SUCCESS;
}

//TODO: investigate if timestamp RFC 6191 is worth implementing
LocalCode TimeWaitS::processEvent(int socket, Tcb& b, SegmentEv& se, RemoteCode& remCode){

  LocalCode s;
  IpPacket& ipP = se.getIpPacket();
  TcpPacket& tcpP = ipP.getTcpPacket();
  
  s = b.checkSequenceNum(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
    
  bool reset = false;
  s = b.checkReset(socket,tcpP,true, remCode, reset);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(reset){
    LocalCode c = remConnOnly(socket, b);
    if(c != LocalCode::SUCCESS) return c;
  }
  
  s = b.checkSec(socket,ipP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  
  if(remCode != RemoteCode::SUCCESS){
    LocalCode c = remConnFlushAll(socket, b, se);
    if(c != LocalCode::SUCCESS) return c;
    return LocalCode::SUCCESS;
  }
  
  s = b.checkSyn(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  s = b.checkAck(socket,tcpP, remCode);
  if(s != LocalCode::SUCCESS) return s;
  if(remCode != RemoteCode::SUCCESS) return LocalCode::SUCCESS;
  
  if(tcpP.getFlag(TcpPacketFlags::FIN)){
    bool sent = b.sendCurrentAck(socket);
    b.startTimeWaitTimer();
    if(sent) return LocalCode::SUCCESS;
    else return LocalCode::SOCKET;
  
  }

  //ignore urgent, data processing, and fin. Peer has already sent a fin and claimed to have nothing more.
  //If we've reached this part the packet didnt have the necessary data to continue the close so it is unexpected.
  remCode = RemoteCode::UNEXPECTEDPACKET;
  return LocalCode::SUCCESS;
}


bool Tcb::addToSendQueue(SendEv& se){

  int sendQueueSize = sendQueueByteCount + se.getData().size();
  if(sendQueueSize < SEND_QUEUE_BYTE_MAX){
      sendQueueByteCount = sendQueueSize;
      sendQueue.push_back(se);
      return true;
  }
  else{
      notifyApp(parentApp, id, TcpCode::RESOURCES, se.getId());
      return false;
  }
  
}

LocalCode ListenS::processEvent(int socket, Tcb& b, SendEv& se){

  ConnPair cp = b.getConnPair();
  if(cp.second.first == UNSPECIFIED || cp.second.second == UNSPECIFIED){
    notifyApp(b.getParApp(), b.getId(), TcpCode::ACTIVEUNSPEC, se.getId());
    return LocalCode::SUCCESS;
  }
  
  b.pickRealIsn(); 
  
  bool ls = b.sendSyn(socket, cp.first, cp.second, false);
  if(ls){
    b.initSenderState(true);
    b.setCurrentState(make_unique<SynSentS>());
    b.addToSendQueue(se);
    return LocalCode::SUCCESS;
  }
  else{
    return LocalCode::SOCKET;
  }
  
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, SendEv& se){
    b.addToSendQueue(se);
    return LocalCode::SUCCESS;
}

LocalCode SynRecS::processEvent(int socket, Tcb& b, SendEv& se){
    b.addToSendQueue(se);
    return LocalCode::SUCCESS;
}

LocalCode EstabS::processEvent(int socket, Tcb& b, SendEv& se){
  b.addToSendQueue(se);
  return LocalCode::SUCCESS;
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, SendEv& se){
  b.addToSendQueue(se);
  return LocalCode::SUCCESS;
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b.getParApp(), b.getId(), TcpCode::CONNCLOSING, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode FinWait2S::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode ClosingS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode LastAckS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, oe.getId());
  return LocalCode::SUCCESS;
}
LocalCode TimeWaitS::processEvent(int socket, Tcb& b, SendEv& oe){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, oe.getId());
  return LocalCode::SUCCESS;
}

bool Tcb::addToRecQueue(ReceiveEv& e){
  if((recQueue.size() + 1) < REC_QUEUE_MAX){
      recQueue.push_back(e);
      return true;
  }
  else{
      notifyApp(parentApp, id, TcpCode::RESOURCES, e.getId());
      return false;
  }
  
}

LocalCode ListenS::processEvent(int socket, Tcb& b, ReceiveEv& e){
    b.addToRecQueue(e);
    return LocalCode::SUCCESS;
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, ReceiveEv& e){
    b.addToRecQueue(e);
    return LocalCode::SUCCESS;
}

LocalCode SynRecS::processEvent(int socket, Tcb& b, ReceiveEv& e){
    b.addToRecQueue(e);
    return LocalCode::SUCCESS;
}


void Tcb::tryProcessReads(){
  for(auto iter = recQueue.begin(); iter != recQueue.end(); iter++){
    if(!processRead(*iter,false)){
      return;
    }
  }
}

bool Tcb::processRead(ReceiveEv& e, bool save){

    //sends should only be processed at or after establishment of the connection
    if(currentState->getNum() < StateNums::ESTAB){
      return false;
    }

    uint32_t readBytes = 0;
    //processing the rec event when there isnt enough data available is only allowed in the close wait state(all the data has already communicated from peer, so can only give what we have left).
    if((arrangedSegmentsByteCount >= e.getAmount()) || currentState->getNum() == StateNums::CLOSEWAIT){
    
      bool evaluateMoreSegments = true;  
      while(evaluateMoreSegments && !arrangedSegments.empty()){
        TcpSegmentSlice& slice = arrangedSegments.front();
        while((slice.getData().size() > 0) && (readBytes < e.getAmount())){
          e.getBuffer().push_back(slice.getData().front());
          slice.getData().pop();
          readBytes++;
          arrangedSegmentsByteCount--;
          appNewData++;
        }
        
        if(slice.getData().size() == 0){
          arrangedSegments.pop_front();
          if(slice.isPush()){
            pushSeen = true;
          }
        }
        
        if(readBytes == e.getAmount()){
          evaluateMoreSegments = false;
        }
        
      }
      
      if(rUp > appNewData){
        if(!urgentSignaled){
          notifyApp(parentApp, id, TcpCode::URGENTDATA, e.getId());
          urgentSignaled = true;
        }
      }
      else{
        urgentSignaled = false;
      }
      
    }
    else{
      if(save){ addToRecQueue(e); }
      return false;
    }
    
    updateWindowSWSRec(0);
    return !arrangedSegments.empty();
}

LocalCode EstabS::processEvent(int socket, Tcb& b, ReceiveEv& e){
  b.processRead(e,true);
  return LocalCode::SUCCESS;
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, ReceiveEv& e){
  b.processRead(e,true);
  return LocalCode::SUCCESS;
}

LocalCode FinWait2S::processEvent(int socket, Tcb& b, ReceiveEv& e){
  b.processRead(e,true);
  return LocalCode::SUCCESS;
}

bool Tcb::noIncomingData(){
  return (arrangedSegmentsByteCount == 0);
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, ReceiveEv& e){

    if(b.noIncomingData()){
      notifyApp(b.getParApp(), b.getId(), TcpCode::CONNCLOSING, e.getId());
      return LocalCode::SUCCESS;
    }
    
    b.processRead(e,true);
    return LocalCode::SUCCESS;
}

LocalCode ClosingS::processEvent(int socket, Tcb& b, ReceiveEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, e.getId());
  return LocalCode::SUCCESS;
}

LocalCode LastAckS::processEvent(int socket, Tcb& b, ReceiveEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, e.getId());
  return LocalCode::SUCCESS;
}

LocalCode TimeWaitS::processEvent(int socket, Tcb& b, ReceiveEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, e.getId());
  return LocalCode::SUCCESS;
}

void Tcb::respondToReads(TcpCode c){
  for(auto iter = recQueue.begin(); iter < recQueue.end(); iter++){
    ReceiveEv& rEv = *iter;
    notifyApp(parentApp, id, c, rEv.getId());
  }
}

void Tcb::respondToSends(TcpCode c){
  for(auto iter = sendQueue.begin(); iter < sendQueue.end(); iter++){
    SendEv& sEv = *iter;
    notifyApp(parentApp, id, c ,sEv.getId());
  }
}

bool Tcb::addToRetransmit(TcpPacket p){
  retransmit.push_back(p);
  return true;
}

LocalCode ListenS::processEvent(int socket, Tcb& b, CloseEv& e){
  b.respondToReads(TcpCode::CLOSING);
  removeConn(b);
  return LocalCode::SUCCESS;
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, CloseEv& e){

  b.respondToReads(TcpCode::CLOSING);
  b.respondToSends(TcpCode::CLOSING);
  removeConn(b);
  return LocalCode::SUCCESS;
}

bool Tcb::noSendsOutstanding(){
  return sendQueue.empty();
}

bool Tcb::noClosesOutstanding(){
  return closeQueue.empty();
}

bool Tcb::noRetransmitsOutstanding(){
  return retransmit.empty();
}

void Tcb::registerClose(CloseEv& e){
  closeQueue.push_back(e);
}

LocalCode SynRecS::processEvent(int socket, Tcb& b, CloseEv& e){

  if(b.noSendsOutstanding()){
    bool ls = b.sendFin(socket);
    b.setCurrentState(make_unique<FinWait1S>());
    if(ls) return LocalCode::SUCCESS;
    else return LocalCode::SOCKET;
  }
  else{
    b.registerClose(e);
    return LocalCode::SUCCESS;
  }
  
}

LocalCode EstabS::processEvent(int socket, Tcb& b, CloseEv& e){

  if(b.noSendsOutstanding()){
    bool ls = b.sendFin(socket);
    b.setCurrentState(make_unique<FinWait1S>());
    if(ls) return LocalCode::SUCCESS;
    else return LocalCode::SOCKET;
  }
  else{
    b.registerClose(e);
    b.setCurrentState(make_unique<FinWait1S>());
    return LocalCode::SUCCESS;
  }
  
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, e.getId());
  return LocalCode::SUCCESS;
}

LocalCode FinWait2S::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, e.getId());
  return LocalCode::SUCCESS;
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, CloseEv& e){

  if(b.noSendsOutstanding()){
    bool ls = b.sendFin(socket);
    b.setCurrentState(make_unique<LastAckS>());
    if(ls) return LocalCode::SUCCESS;
    else return LocalCode::SOCKET;
  }
  else{
    b.registerClose(e);
    b.setCurrentState(make_unique<LastAckS>());
    return LocalCode::SUCCESS;
  }

}

LocalCode ClosingS::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, e.getId());
  return LocalCode::SUCCESS;
}

LocalCode LastAckS::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, e.getId());
  return LocalCode::SUCCESS;
}

LocalCode TimeWaitS::processEvent(int socket, Tcb& b, CloseEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNCLOSING, e.getId());
  return LocalCode::SUCCESS;
}


LocalCode ListenS::processEvent(int socket, Tcb& b, AbortEv& e){

  b.respondToReads(TcpCode::CONNRST);
  removeConn(b);
  return LocalCode::SUCCESS;
}

LocalCode SynSentS::processEvent(int socket, Tcb& b, AbortEv& e){

  b.respondToReads(TcpCode::CONNRST);
  b.respondToSends(TcpCode::CONNRST);
  
  removeConn(b);
  return LocalCode::SUCCESS;
}

LocalCode Tcb::normalAbortLogic(int socket, AbortEv& e){

  bool ls = sendReset(socket, lP, rP, 0, false, sNxt);
  
  respondToReads(TcpCode::CONNRST);
  respondToSends(TcpCode::CONNRST);
  
  retransmit.clear();
  removeConn(*this);
  if(ls) return LocalCode::SUCCESS;
  else return LocalCode::SOCKET;

}

LocalCode SynRecS::processEvent(int socket, Tcb& b, AbortEv& e){
  return b.normalAbortLogic(socket,e);
}

LocalCode EstabS::processEvent(int socket, Tcb& b, AbortEv& e){
  return b.normalAbortLogic(socket,e);
}

LocalCode FinWait1S::processEvent(int socket, Tcb& b, AbortEv& e){
  return b.normalAbortLogic(socket,e);
}

LocalCode FinWait2S::processEvent(int socket, Tcb& b, AbortEv& e){
  return b.normalAbortLogic(socket,e);
}

LocalCode CloseWaitS::processEvent(int socket, Tcb& b, AbortEv& e){
  return b.normalAbortLogic(socket,e);
}

LocalCode ClosingS::processEvent(int socket, Tcb& b, AbortEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::OK, e.getId());
  return LocalCode::SUCCESS;
}

LocalCode LastAckS::processEvent(int socket, Tcb& b, AbortEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::OK, e.getId());
  return LocalCode::SUCCESS;
}

LocalCode TimeWaitS::processEvent(int socket, Tcb& b, AbortEv& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::OK, e.getId());
  return LocalCode::SUCCESS;
}

//assumes active rem unspec has already been checked for
Tcb Tcb::buildTcbFromOpen(bool& success, App* app, int socket, LocalPair lP, RemotePair rP, int& createdId, OpenEv ev){

  bool passive = ev.isPassive();
  Tcb newConn(app, lP, rP, passive);
  if(passive){
    newConn.setCurrentState(make_unique<ListenS>());
  }
  else{
    newConn.setCurrentState(make_unique<SynSentS>());
  }
  
  if(lP.second == UNSPECIFIED){
    uint16_t chosenPort = pickDynPort();
    if(chosenPort != UNSPECIFIED){
      lP.second = chosenPort;
      newConn.lP = lP;
    }
    else{
      notifyApp(newConn.getParApp(), newConn.getId(), TcpCode::RESOURCES, ev.getId());
      success = false;
      return newConn;
    }
  }
  if(lP.first == UNSPECIFIED){
    uint32_t chosenAddr = pickDynAddr(); 
    lP.first = chosenAddr;
    newConn.lP = lP;
  }
  
  ConnPair p(lP,rP);
  int id = 0;
  bool idWorked = pickId(id);
  if(idWorked) idMap[id] = p;
  else{
    notifyApp(newConn.getParApp(), newConn.getId(), TcpCode::RESOURCES,ev.getId());
    success = false;
    return newConn;
  }
    
  if(!passive){
    newConn.pickRealIsn();
  
    bool ls = newConn.sendSyn(socket,newConn.lP,newConn.rP,false);
    if(ls){
      newConn.sUna = newConn.iss;
      newConn.sNxt = newConn.iss + 1;
      newConn.setCurrentState(make_unique<SynSentS>());
    }
    else{
      reclaimId(id);
      success = false;
      return newConn;
    }

  }
  
  newConn.id = id;
  createdId = id;
  success = true;
  return newConn;
}

