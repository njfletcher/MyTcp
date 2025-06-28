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
//range from 0 to max_val(int)
unordered_set<int> usedIds;
unordered_map<int, pair<LocalPair,RemotePair>> idMap;
uint32_t bestLocalAddr;

//if an active open, assumes initial packet has been sent.
Tcb::Tcb(LocalPair l, RemotePair r, int passive) : lP(l), rP(r), passiveOpen(passive) {}

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
    if(!usedIds.contains(i)){
      usedIds.insert(i);
      return i;
    }
  }
  return -1;
}

/*
reclaimId
reclaims id so that it can be used with new connections
assumes the id is a valid one that is in use
*/
void reclaimId(int id){

  usedIds.erase(id);
  idMap.erase(id);
  
}

/*pickDynAddr
ideally will pick best address based on routing tables.
for right now this just returns a default address
*/
uint32_t pickDynAddr(){

  return bestLocalAddr;
}

/*
open
models the open action for the application interface
creates connection and kicks off handshake(if active open)
returns -1 for error or a unique identifier analogous to a file descriptor.
*/
int open(ConnectionMap& m, int passive, LocalPair lP, RemotePair rP){

  Tcb b(lP, rP, passive);
  if(passive){
    b.currentState = listen;
  }
  else{
    //unspecified remote info in active open does not make sense
    if(rP.first == Unspecified || rP.second == Unspecified) return -1;
    b.currentState = synSent;
  }
  
  if(lP.second == Unspecified){
    uint16_t chosenPort = pickDynPort();
    if(chosenPort != Unspecified){
      lP.second = chosenPort;
      b.lP = lP;
    }
    else return -1;
  }
  if(lP.first == Unspecified){
    uint32_t chosenAddr = pickDynAddr(); 
    lP.first = chosenAddr;
    b.lP = lP;
  }
  
  if(m.contains(lP)){
    //duplicate connection
    if(m[lP].contains(rP){
      return -1;
    }
  }
  else m[lP] = unordered_map<RemotePair, Tcb>();
  
  int id = pickId(s);
  pair p(LocalPair,RemotePair);
  if(id != -1) idMap[id] = p;
  else return -1;
  
  pickRealIsn(b);
  b.rWnd = 8192;
  
  //finally need to send initial syn packet in active open because state is set to synOpen
  if(!passive){
  
    vector<TcpOption> v;
    vector<uint8_t> v1;
    TcpPacket p;
  
    p.setFlags(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,   0x0).setSrcPort(lP.second).setDestPort(rP.second).setSeq(b.iss).setAck(0x00).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(v).setPayload(v1).setRealChecksum(lP.first,rP.first);
  
    if(sendPacket(socket,b.destAddress, p) != -1){
      b.sUna = p.getSeqNum();
      b.sNxt = p.getSeqNum() + p.getSegSize();
      b.retransmit.push_back(p);
    }
    else{
      reclaimId(id);
      return -1;
    }
  }

  m[lP][rP] = b;
  return id;
  
}


/*
sendReset-
This method sends a rst packet, given its acknum, ackflag, and seqnum. These fields are handled
differently based on which scenario a reset is needed in, so this logic is assumed to take place
outside of this method. Any logic involving moving a connection to the next state is also
assumed to be handled outside of this method.
*/

int sendReset(int socket, ConnectionTuple t, uint32_t ackNum, uint8_t ackFlag, uint32_t seqNum){

  TcpPacket sPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  
  sPacket.setFlags(0x0, 0x0, 0x0, ackFlag, 0x0, 0x0, 0x0,    0x0).setSrcPort(get<sPort>(t)).setDestPort(get<dPort>(t)).setSeq(seqNum).setAck(ackNum).setDataOffset(0x05).setReserved(0x00).setWindow(0x00).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(get<sAddr>(t), get<dAddr>(t));
      
  if(sendPacket(socket,get<dAddr>(t),sPacket) != -1){
    //if(sPacket.payload.size()) b.retransmit.push_back(sPacket);
    return 0;
  }
  else return -1;
    
}

/*
multiplexIncoming-
Upon notification of incoming packet on interface, this method
checks details of the packet and gives it to correct connection, or sends reset if it does not belong
to a valid connection
*/

void multiplexIncoming(unordered_map<ConnectionTuple, Tcb>& connections, int socket){

  IpPacket retPacket;
  if(recPacket(socket, retPacket) != -1){
    TcpPacket& p = retPacket.getTcpPacket();

    uint32_t sourceAddress = retPacket.getDestAddr();
    uint32_t destAddress = retPacket.getSrcAddr();
    uint16_t sourcePort = p.getDestPort();
    uint16_t destPort = p.getSrcPort();
    
    ConnectionTuple t(sourceAddress, sourcePort, destAddress, destPort);
    if(connections.contains(t)){
      Tcb& b = connections[t];
      b.currentState(b,p,socket);
    }
    //fictional closed state
    else{
      if(!p.getFlag(TcpPacketFlags::rst)){
      
        if(p.getFlag(TcpPacketFlags::ack)){
          sendReset(socket, t, 0, 0, p.getAckNum());
        }
        else{
          sendReset(socket,t, p.getSeqNum() + p.getSegSize(),1,0);
        }
      }
      else{
        //possible reset processing
      }
    }
  
  }
  
}

/*
entryTcp-
Starts the tcp implementation, equivalent to a tcp module being loaded.
the interface socket, polling of this socket, and all connections start at this point.
returns -1 if failure, otherwise will run until unloaded by user and return 0
*/

//in the future bind this to all available source addresses and poll all of them, not just one address
int entryTcp(char* sourceAddr){

  uint32_t sourceAddress = toAltOrder<uint32_t>(inet_addr(sourceAddr));
  int socket =  bindSocket(sourceAddress);
  if(socket < 0){
    return -1;
  }
  ConnectionMap connections;
  
  struct pollfd pollItem;
  pollItem.fd = socket;
  pollItem.events = POLLIN; //read
  while(true){
  
    int numRet = poll(&pollItem, 1, -1);
    if((numRet > 0) && (pollItem.revents & POLLIN)){
      multiplexIncoming(connections, socket);
    }
  
  }
  
  return 0;
}

/* tcp state functions
require block, packet, action, data, socket signature 
*/

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

int synSent(Tcb& b, TcpPacket& p, int socket){

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

int listen(Tcb& b, TcpPacket& p, int socket){

  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  //if im in the listen state, I havent sent anything. so any ack at all is an unacceptable ack
  if(p.getFlag(TcpPacketFlags::ack)){
    sendReset(socket, b.connT, 0, 0, p.getAckNum());
    return 0;
  }
  
  uint32_t segLen = p.getSegSize();
  b.sWnd = p.getWindow();
  b.irs = p.getSeqNum();
  
  b.rNxt = p.getSeqNum() + segLen;
    
  if(p.getFlag(TcpPacketFlags::syn)){
    
  sPacket.setFlags(0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x1,    0x0).setSrcPort(packetSrcPort).setDestPort(packetDestPort).setSeq(b.iss).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.sourceAddress, b.destAddress);
      
    if(sendPacket(socket,b.destAddress,sPacket) != -1){
      b.sUna = sPacket.getSeqNum();
      b.sNxt = sPacket.getSeqNum() + sPacket.getSegSize();
      if(sPacket.payload.size()) b.retransmit.push_back(sPacket);
      b.currentState = synReceived;
    }
  }
  else{
      //error or possible reset
  }

}

