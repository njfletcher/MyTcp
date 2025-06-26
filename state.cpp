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
#include <tuple>
#include <poll.h>

using namespace std;


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

int entryTcp(char* sourceAddr){

  uint32_t sourceAddress = toAltOrder<uint32_t>(inet_addr(sourceAddr));
  int socket =  bindSocket(sourceAddress);
  if(socket < 0){
    return -1;
  }
  unordered_map<ConnectionTuple, Tcb> connections;
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
/*
void startFuzzSequence(unordered_map<pair<uint32_t, uint32_t>, uint8_t>& connections, char* destAddr, char* srcAddr, int socket){
  
  Tcb b;
  b.destAddress = toAltOrder<uint32_t>(inet_addr(destAddr));
  b.sourceAddress = toAltOrder<uint32_t>(inet_addr(srcAddr));
  
  char validConnection = 0;
  while(!validConnection){
    unsigned char srcPort[4];
    if(RAND_bytes(srcPort, 4) < 1){
      ERR_print_errors_fp(stderr);
      return -1;
    }
    unsigned char dstPort[4];
    if(RAND_bytes(dstPort, 1) < 1){
      ERR_print_errors_fp(stderr);
      return -1;
    }
    uint32_t sPortConv = unloadBytes<uint32_t>(srcPort,0);
    uint32_t dPortConv = unloadBytes<uint32_t>(dstPort,0);
    if(sPortConv < portThreshold) sPortConv = sPortConv + portThreshold;
    if(dPortConv < portThreshold) dPortConv = dPortConv + portThreshold;
    pair<uint32_t, uint32_t> p(sPortConv, dPortConv);
    if(!connections.contains(p)){
      connections[p] = 1;
      validConnection = 1;
    }
  }
  
  unsigned char passive = 0;
  if(RAND_bytes(passive, 1) < 1){
    ERR_print_errors_fp(stderr);
    return -1;
  }
  passive = passive % 2;
  closed(b, passive, socket);
  
}
*/

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
    
  //if(!verifyRecWindow(b.rWnd, b.rNxt, p.seqNum, segLen)){
  //  return -1;
  //}
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


void closed(Tcb& b, int passive, int socket){
  
  pickRealIsn(b);
  b.rWnd = 8192;
  
  if(!passive){
    vector<TcpOption> v;
    vector<uint8_t> v1;
    TcpPacket p;
  
    p.setFlags(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,   0x0).setSrcPort(b.sourcePort).setDestPort(b.destPort).setSeq(b.iss).setAck(0x00).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(v).setPayload(v1).setRealChecksum(b.sourceAddress,   b.destAddress);
  
    if(sendPacket(socket,b.destAddress, p) != -1){
      b.sUna = p.getSeqNum();
      b.sNxt = p.getSeqNum() + p.getSegSize();
      b.retransmit.push_back(p);
      synSent(b,socket);
    }
  
  }
  else listen(b, socket);
  
}


