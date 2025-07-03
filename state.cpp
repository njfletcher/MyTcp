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

//if an active open, assumes initial packet has been sent.
Tcb::Tcb(LocalPair l, RemotePair r, uint8_t passive) : lP(l), rP(r), passiveOpen(passive) {}

void printError(Code c){
  cout << "error: ";
  switch(c){
    case ActiveUnspec:
      cout << "remote socket unspecified" << endl;
      break;
    case Resources:
      cout << "insufficient resources" << endl;
      break;
    case DupConn:
      cout << "connection already exists" << endl;
      break;
    case RawSend:
      cout << "problem with raw socket sending" <<endl;
      break;
    case ProgramError:
      cout << "problem with usage of program" << endl;
      break;
    case BadIncPacket:
      cout << "incoming packet has problems" << endl;
      break;
    case ConnRst:
      cout << "connection reset" << endl;
      break;
    default:
      cout << "unknown" << endl;
  }
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

int verifyRecWindow(uint32_t rWnd, uint32_t rNxt, uint32_t seqNum, uint32_t segLen){

  if(seqLen > 0){
    if(rWnd >0){
      uint32_t lastByte = seqNum + segLen -1;
      return (rNxt <= lastByte && lastByte < (rNxt + rWnd));
    
    }
    else return 0;
  
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
sendReset-
This method sends a rst packet, given its acknum, ackflag, and seqnum. These fields are handled
differently based on which scenario a reset is needed in, so this logic is assumed to take place
outside of this method. Any logic involving moving a connection to the next state is also
assumed to be handled outside of this method.
*/

Code sendReset(int socket, LocalPair lP, RemotePair rP, uint32_t ackNum, uint8_t ackFlag, uint32_t seqNum){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  sPacket.setFlags(0x0, 0x0, 0x0, ackFlag, 0x0, 0x0, 0x0,    0x0).setSrcPort(lP.second).setDestPort(rP.second).setSeq(seqNum).setAck(ackNum).setDataOffset(0x05).setReserved(0x00).setWindow(0x00).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(lP.first, rP.first);
      
  if(sendPacket(socket, rP.first, sPacket) != -1){
    //if(sPacket.payload.size()) b.retransmit.push_back(sPacket);
    return Code::Success;
  }
  else return Code::RawSend;
    
}

/*
sendFirstSyn
sends the initiating syn packet needed by an active open
made a separate method because it has relatively hardcoded values/effects and
the rfcs do not recommend sending data with it.
*/
Code sendFirstSyn(Tcb& b, int socket){

    vector<TcpOption> v;
    TcpPacket p;
  
    p.setFlags(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,   0x0).setSrcPort(b.lP.second).setDestPort(b.rP.second).setSeq(b.iss).setAck(0x00).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(v).setRealChecksum(b.lP.first,b.rP.first);
  
    if(sendPacket(socket, b.rP.first, p) != -1){
      b.sUna = b.iss;
      b.sNxt = b.iss + 1;
      return Code::Success;
    }
    else{
      return Code::RawSend;
    }
}

/*
open
models the open action for the application interface
creates connection and kicks off handshake(if active open)
returns negative code for error or a unique identifier analogous to a file descriptor.
*/
int open(uint8_t passive, LocalPair lP, RemotePair rP){

  Tcb newConn(lP, rP, passive);
  if(passive){
    newConn.currentState = State::Listen;
    newConn.stateLogic = listen;
  }
  else{
    //unspecified remote info in active open does not make sense
    if(rP.first == Unspecified || rP.second == Unspecified) static_cast<int>(Code::ActiveUnspec);
    newConn.currentState = State::SynSent;
    newConn.stateLogic = synSent;
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
      return static_cast<int>(oldConn.stateLogic(socket, oldConn, nullptr, Event::Open, &passive)); 
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
    Code c = sendFirstSyn(newConn,socket);
    if(c != Code::Success){
      reclaimId(id);
      return static_cast<int>(c);
    }
    b.stateLogic = synSent;
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
      if(connections[lP].contains(rP)) return b.stateLogic(socket,connections[lP][rP],&retPacket,Event::none,nullptr);
      RemotePair addrUnspec(Unspecified, rP.second);
      if(connections[lP].contains(addrUnspec)) return b.stateLogic(socket,connections[lP][addrUnspec],&retPacket,Event::none,nullptr);
      RemotePair portUnspec(rP.first, Unspecified);
      if(connections[lP].contains(portUnspec)) return b.stateLogic(socket,connections[lP][portUnspec],&retPacket,Event::none,nullptr);
      RemotePair fullUnspec(Unspecified, Unspecified);
      if(connections[lP].contains(fullUnspec)) return b.stateLogic(socket,connections[lP][fullUnspec],&retPacket,Event::none,nullptr);
    }
    
    //if we've gotten to this point no conn exists: fictional closed state
    if(!p.getFlag(TcpPacketFlags::rst)){
      if(p.getFlag(TcpPacketFlags::ack)){
        return sendReset(socket, lP, rP, 0, 0, p.getAckNum());
      }
      else{
        return sendReset(socket, lP, rP, p.getSeqNum() + p.getSegSize(),1,0);
      }
    }
    else return Code::BadIncPacket; //per rfc 9293 3.10.7 rst packet should be discarded, so nothing else to do if it is a rst.
    
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

int closeWait(Tcb& b, TcpPacket& p , int socket){

}

int established(Tcb& b, TcpPacket& p , int socket){

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

Code synSent(int socket, Tcb& b, IpPacket* pPtr, Event ev, uint8_t* evData){

  if(pPtr != nullptr){
    IpPacket& ipP = *pPtr;
    TcpPacket& tcpP = ipP.getTcpPacket();
    RemotePair recPair(ipP.getSrcAddr(), tcpP.getSrcPort());
    
    uint8_t ackFlag = tcpP.getFlag(TcpPacketFlags::ack);
    if(ackFlag){
      uint32_t ackN = tcpP.getAckNum();
      if(ackN <= b.iss || ackN > b.sNxt){
        if(!tcpP.getFlag(TcpPacketFlags::rst)) sendReset(socket, b.lP, b.rP, 0, 0, ackN);
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
    
    
    vector<TcpOption> options;
    vector<uint8_t> data;
    TcpPacket sPacket;
  
    uint32_t segLen = p.getSegSize();
    b.sWnd = p.getWindow();
    b.irs = p.getSeqNum(); 
    if(!verifyRecWindow(b.rWnd, b.rNxt, p.seqNum, segLen)){
      return -1;
    }
  
    b.rNxt = p.getSeqNum() + segLen;
    
    if(p.getFlag(TcpPacketFlags::syn)){
    
      if(p.getFlag(TcpPacketFlags::ack)){
        //standard connection attempt
        
        if(verifyAck(b.sUna, b.sNxt, p.getAckNum()){
          b.sUna = p.getAckNum();
        }
        else{
          sendReset(socket, b.connT, 0, 0, p.getAckNum());
          return 0;
        }
      
        sPacket.setFlags(0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,    0x0).setSrcPort(packetSrcPort).setDestPort(packetDestPort).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.sourceAddress, b.destAddress);
      
        if(sendPacket(socket,b.destAddress,sPacket) != -1){
            b.sNxt = b.sNxt + sPacket.payload.size(); // ack doesnt affect seq num
            if(sPacket.payload.size()) b.retransmit.push_back(sPacket);
            b.currentState = established;
        }
    
      }
      else{
        //simultaneous connection attempt
        sPacket.setFlags(0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,    0x0).setSrcPort(packetSrcPort).setDestPort(packetDestPort).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.sourceAddress, b.destAddress);
      
        if(sendPacket(socket,b.destAddress,sPacket) != -1){
            b.sNxt = b.sNxt + sPacket.payload.size(); // ack doesnt affect seq num
            if(sPacket.payload.size()) b.retransmit.push_back(sPacket);
            b.currentState = synReceived;
        }
      }
    
    }
    //if in syn-sent need to be sent a syn at the very least: send rst
    else{
      if(p.getFlag(TcpPacketFlags::ack)){
        sendReset(socket, b.connT, 0, 0, p.getAckNum());
      }
      else{
        sendReset(socket,b.connT, p.getSeqNum() + p.getSegSize(),1,0);
      }
    }
  }
  else{
      switch(ev){
      case Event::None:
        return Code::ProgramError;
      case Event::Open:
        return Code::DupConn;
      case default:
        return Code::DupConn;
    }
  
  }
   
}

Code listen(int socket, Tcb& b, IpPacket* pPtr, Event ev, uint8_t* evData){

  if(pPtr != nullptr){
    IpPacket& ipP = *pPtr;
    TcpPacket& tcpP = ipP.getTcpPacket();
    RemotePair recPair(ipP.getSrcAddr(), tcpP.getSrcPort());
    
    //if im in the listen state, I havent sent anything, so rst could not be referring to anything valid.
    if(tcpP.getFlag(TcpPacketFlags::rst)){
      return Code::BadIncPacket;
    }
  
    //if im in the listen state, I havent sent anything. so any ack at all is an unacceptable ack
    if(tcpP.getFlag(TcpPacketFlags::ack)){
      sendReset(socket, b.lP, recPair, 0, 0, tcpP.getAckNum());
      return Code::BadIncPacket;
    }
  
    if(tcpP.getFlag(TcpPacketFlags::syn)){

      uint32_t segLen = tcpP.getSegSize();
      pickRealIsn(b);
      tcpP.irs = tcpP.getSeqNum();
      tcpP.rNxt = tcpP.getSeqNum() + 1;
      
      vector<TcpOption> options;
      vector<uint8_t> data;
      TcpPacket sPacket;
      
      sPacket.setFlags(0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x1,    0x0).setSrcPort(b.lP.second).setDestPort(recPair.second).setSeq(b.iss).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.lP.first, recPair.first);
      
      if(sendPacket(socket,recPair.first,sPacket) != -1){
        b.sUna = b.iss;
        b.sNxt = b.iss + 1;
        b.stateLogic = synReceived;
        if(b.rP.first == Unspecified) b.rP.first = recPair.first;
        if(b.rP.second == Unspecified) b.rP.second = recPair.second;
        //TODO 3.10.7.2 possibly trigger another event for processing of data and other control flags here: maybe forward packet without syn and ack flags set?
        return Code::Success;
      }
      else return Code::RawSend;
    }
    else return Code::BadIncPacket;
    
  }
  else{
  
    switch(ev){
      case Event::None:
        return Code::ProgramError;
      case Event::Open:
        uint8_t passive = evData[0];
        if(!passive){
          if(b.rP.first == Unspecified || b.rP.second == Unspecified) return Code::ActiveUnspec;
          Code c = sendFirstSyn(b,socket);  
          if(c != Code::Success) return c;
          b.passiveOpen = 0;
          b.stateLogic = synSent;
          return Code::Success;
        }
        else return Code::DupConn;
      case default:
        return Code::DupConn;
    }
  
  }

}




