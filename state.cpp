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

using namespace std;

//range from dynPortStart to dynPortEnd
unordered_set<uint16_t> usedPorts;
//ids range from 0 to max val of int
unordered_map<int, pair<LocalPair,RemotePair>> idMap;
uint32_t bestLocalAddr;
ConnectionMap connections;

Tcb::Tcb(LocalPair l, RemotePair r, bool passive) : lP(l), rP(r), passiveOpen(passive) {}

void printError(Code c){
  string s = "error: ";
  switch(c){
    case ActiveUnspec:
      s += "remote socket unspecified";
      break;
    case Resources:
      s += "insufficient resources";
      break;
    case DupConn:
      s += "connection already exists";
      break;
    case RawSend:
      s += "problem with raw socket sending";
      break;
    case ProgramError:
      s += "problem with usage of program";
      break;
    case BadIncPacket:
      s += "incoming packet has problems";
      break;
    case ConnRst:
      s += "connection reset";
      break;
    case ConnRef:
      s += "connection refused";
      break;
    case ConnClosing:
      s += "connection closing";
      break;
    default:
      s += "unknown";
      
    cout << s << endl;
  }
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
      uint32_t lastByte = seqNum + segLen -1;
      return (b.rNxt <= lastByte && lastByte < (b.rNxt + b.rWnd));
    
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

Code sendReset(int socket, LocalPair lP, RemotePair rP, uint32_t ackNum, bool ackFlag, uint32_t seqNum){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  if(ackFlag){
    sPacket.setFlag(TcpPacketFlags::ack);
  }
  sPacket.setFlag(TcpPacketFlags::rst).setSrcPort(lP.second).setDestPort(rP.second).setSeq(seqNum).setAck(ackNum).setDataOffset(0x05).setReserved(0x00).setWindow(0x00).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(lP.first, rP.first);
      
  if(sendPacket(socket, rP.first, sPacket) != -1){

    return Code::Success;
  }
  else return Code::RawSend;
    
}

Code ListenS::processEvent(int socket, Tcb& b, OpenEv& oe){

  vector<TcpOption> v;
  TcpPacket p;
  bool passive = oe.passive;
  if(!passive){
    if(b.rP.first == Unspecified || b.rP.second == Unspecified) return Code::ActiveUnspec; p.setFlag(TcpPacketFlags::syn).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.iss).setAck(0x00).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(v).setRealChecksum(b.lP.first,b.rP.first);
  
    if(sendPacket(socket, b.rP.first, p) != -1){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      b.passiveOpen = false;
      b.currentState = SynSentS();
      return Code::Success;
    }
    else{
      return Code::RawSend;
    }
    
    
  }
  else return Code::DupConn;
  
}

Code SynSentS::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}
Code SynRecS::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}
Code EstabS::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}
Code FinWait1S::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}
Code FinWait2S::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}
Code CloseWaitS::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}
Code ClosingS::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}
Code LastAckS::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}
Code TimeWaitS::processEvent(int socket, Tcb& b, OpenEv& oe){return Code::DupConn;}


Code ListenS::processEvent(int socket, Tcb& b, SegmentEv& se){

  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();
  RemotePair recPair(ipP.getSrcAddr(), tcpP.getSrcPort());
    
  //if im in the listen state, I havent sent anything, so rst could not be referring to anything valid.
  if(tcpP.getFlag(TcpPacketFlags::rst)){
    return Code::BadIncPacket;
  }
  
  //if im in the listen state, I havent sent anything. so any ack at all is an unacceptable ack
  if(tcpP.getFlag(TcpPacketFlags::ack)){
    sendReset(socket, b.lP, recPair, 0, false, tcpP.getAckNum());
    return Code::BadIncPacket;
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn)){
  
    uint32_t segLen = tcpP.getSegSize();
    if(!checkSecurity(b, ipP)){
      sendReset(socket, b.lP, recPair, tcpP.getSeqNum() + seqLen , true, 0);
      return Code::BadIncPacket;
    }
    
    pickRealIsn(b);
    tcpP.irs = tcpP.getSeqNum();
    tcpP.rNxt = tcpP.getSeqNum() + 1;
      
    vector<TcpOption> options;
    vector<uint8_t> data;
    TcpPacket sPacket;
      sPacket.setFlag(TcpPacketFlags::syn).setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(recPair.second).setSeq(b.iss).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, recPair.first);
      
    if(sendPacket(socket,recPair.first,sPacket) != -1){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      b.stateLogic = SynRecS();
      if(b.rP.first == Unspecified) b.rP.first = recPair.first;
      if(b.rP.second == Unspecified) b.rP.second = recPair.second;
      //TODO 3.10.7.2 possibly trigger another event for processing of data and other control flags here: maybe forward packet without syn and ack flags set?
      return Code::Success;
    }
    else return Code::RawSock;
  }
  else return Code::BadIncPacket;

}


Code SynSentS::processEvent(int socket, Tcb& b, SegmentEv& se){

  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();

  uint8_t ackFlag = tcpP.getFlag(TcpPacketFlags::ack);
  if(ackFlag){
    uint32_t ackN = tcpP.getAckNum();
    if(ackN <= b.iss || ackN > b.sNxt){
      if(!tcpP.getFlag(TcpPacketFlags::rst)) sendReset(socket, b.lP, b.rP, 0, false, ackN);
      return Code::BadIncPacket;
    }
  }
    
  uint32_t seqN = tcpP.getSeqNum();
  if(tcpP.getFlag(TcpPacketFlags::rst)){
    //RFC 5961, preventing blind reset attack. TODO: research if anything else is needed.
    if(seqN != b.rNxt) return Code::BadIncPacket;
    
    if(ackFlag){
      removeConn(b);
      return Code::ConnRst;
    }
    else return Code::BadIncPacket; 
    
  }
  
  if(!checkSecurity(b,ipP)){
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      sendReset(socket, b.lP, b.rP, seqN + tcpP.getSegSize(),true,0);
    }
    return Code::BadIncPacket;
  }
  
  if(p.getFlag(TcpPacketFlags::syn)){
  
    b.sWnd = tcpP.getWindow();
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
      
      if(sendPacket(socket,b.rP.first,sPacket) != -1){
          b.currentState = EstabS();
          return Code::Success;
      }
      else return Code::RawSock;
    
    }
    else{
      //simultaneous connection attempt
      sPacket.setFlag(TcpPacketFlags::syn).setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.iss).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      if(sendPacket(socket,b.rP.first,sPacket) != -1){
        b.currentState = synReceived;
        //TODO: sNxt?
        return Code::Success;
      }
      else return Code::RawSock;
    }
    
  }
  //need at least a syn or a rst
  else return Code::BadIncPacket;
  
}

Code SynRecS::processEvent(int socket, Tcb& b, SegmentEv& se){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  IpPacket& ipP = se.packet;
  TcpPacket& tcpP = ipP.getTcpPacket();
  if(!verifyRecWindow(b,tcpP)){
    if(!tcpP.getFlag(TcpPacketFlags::rst)){
    sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      if(sendPacket(socket,b.rP.first,sPacket) != -1){
        return Code::BadIncPacket;
      }
      else return Code::RawSock;
      
    }
    return Code::BadIncPacket;
  }
  
  if(tcpP.getFlag(TcpPacketFlags::rst)){
  
      //check for RFC 5961S3 rst attack mitigation. Step 1 already handled above so seq is assumed to at least be in window.
      if(tcpP.getSeqNum() != b.rNxt){
      sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
        if(sendPacket(socket,b.rP.first,sPacket) != -1){
          return Code::BadIncPacket;
        }
        else return Code::RawSock;
        
      }
      
      if(b.passiveOpen){
        b.currentState = ListenS();
        return Code::Success;
      }
      else{
        removeConn(b);
        return Code::ConnRef;
      }
      //TODO : flush retransmission queue
      
  }
  
  if(!checkSecurity(b,ipP)){
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
    }
    else{
      sendReset(socket, b.lP, b.rP, tcpP.getSeqNum() + tcpP.getSegSize(),true,0);
    }
    return Code::BadIncPacket;
  }
  
  if(tcpP.getFlag(TcpPacketFlags::syn){
  
    if(b.passiveOpen){
      b.currentState = ListenS();
      return Code::Success;
    }
    
    //challenge ack recommended by RFC 5961  
sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    if(sendPacket(socket,b.rP.first,sPacket) != -1){
      return Code::BadIncPacket;
    }
    else return Code::RawSock;
    
  }
  
  
  if(tcpP.getFlag(TcpPacketFlags::ack){
  
    uint32_t ackNum = tcpP.getAckNum();
  
    //RFC 5661S5 injection attack check
    if(!((ackNum >= (b.sUna - b.maxSWnd)) && (ackNum <= b.sNxt))){
       sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
      if(sendPacket(socket,b.rP.first,sPacket) != -1){
        return Code::BadIncPacket;
      }
      else return Code::RawSock;
      
    }
      
    if((ackNum > b.sUna) && (ackNum <= b.sNxt)){
      b.currentState = EstabS();
      b.sWnd = tcpP.getWindow();
      b.sWl1 = tcp.getSeqNum();
      b.sWl2 = ackNum();
      //TODO trigger further processing event
      return Code::Success;
    }
    else{
      Code c = sendReset(socket, b.lP, b.rP, 0, false, tcpP.getAckNum());
      if(c != Code::Success) return c;
      else return Code::BadIncPacket;
      
    }
  }
  else return Code::BadIncPacket;
  
  if(tcpP.getFlag(TcpPacketFlags::fin)){
    
    b.rNxt = tcpP.getSeqNum() + 1; //advancing rNxt over fin
    sPacket.setFlag(TcpPacketFlags::ack).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, b.rP.first);
      
    if(sendPacket(socket,b.rP.first,sPacket) != -1){
      b.currentState = CloseWaitS();
      //TODO: return conn closing to any pending recs and push any waiting segments.
      return Code::ConnClosing;
    }
    else return Code::RawSock;
    
    
  }
  
  return Code::Success;
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







