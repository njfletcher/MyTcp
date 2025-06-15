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

int pickInsecureIsn(Tcb& block){
  block.iss = 0;
  return 0;
}

int pickPrevIsn(Tcb& block, uint32_t prev){
  block.iss = prev;
  return 0;
}

int pickOverflowIsn(Tcb& block){
  block.iss = 0xFFFFFFFF;
  return 0;
}


void synReceived(Tcb& b, int socket){
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

void synSent(Tcb& b, int socket){

  IpPacket retPacket;
  vector<TcpOption> options;
  vector<uint8_t> data;
  TcpPacket sPacket;
  
  if(recPacket(socket,retPacket) != -1){
    TcpPacket& p = retPacket.getTcpPacket();
    
    uint32_t segLen = p.payload.size() + p.getFlag(TcpPacketFlags::syn) + p.getFlag(TcpPacketFlags::fin);
    b.sWnd = p.getWindow();
    b.irs = p.getSeqNum();
    b.rNxt = p.getSeqNum() + segLen;
    
    //verify rec window
    
    if(p.getFlag(TcpPacketFlags::syn)){
    
      if(p.getFlag(TcpPacketFlags::ack)){
      
        //verify ack
      
      
      
        sPacket.setFlags(0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,    0x0).setSrcPort(packetSrcPort).setDestPort(packetDestPort).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.sourceAddress, b.destAddress);
      
        if(sendPacket(socket,b.destAddress,sPacket) != -1){
            b.sUna = sPacket.getSeqNum() + sPacket.payload.size();
            b.sNxt = b.sNxt + sPacket.payload.size(); // ack doesnt affect seq num
            if(sPacket.payload.size()) b.retransmit.push_back(sPacket);
            established(b,socket);
        }
    
        //established
      }
      else{
        //simultaneous connection attempt
        sPacket.setFlags(0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,    0x0).setSrcPort(packetSrcPort).setDestPort(packetDestPort).setSeq(b.sNxt).setAck(b.rNxt).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(options).setPayload(data).setRealChecksum(b.sourceAddress, b.destAddress);
      
        if(sendPacket(socket,b.destAddress,sPacket) != -1){
            b.sUna = sPacket.getSeqNum() + sPacket.payload.size();
            b.sNxt = b.sNxt + sPacket.payload.size(); // ack doesnt affect seq num
            if(sPacket.payload.size()) b.retransmit.push_back(sPacket);
            synReceived(b,socket);
        }
      }
    
    }
    else{
      
      //error or possible reset
    }
    
    
        
}

void closed(char* destAddr, Tcb& b, int passive){

  b.destPort = 22;
  b.destAddress = toAltOrder<uint32_t>(inet_addr(destAddr));
  b.sourcePort = 8879;
  const char src[14] = "192.168.237.4";
  b.sourceAddress = toAltOrder<uint32_t>(inet_addr(src));
  
  //packet ports may be different than block ports(maybe due to some error).
  uint16_t packetSrcPort = 8879;
  uint16_t packetDestPort = 22;
  pickRealIsn(b);

  vector<TcpOption> v;
  vector<uint8_t> v1;
  TcpPacket p;
  b.rWnd = 8192;
  
  p.setFlags(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0).setSrcPort(packetSrcPort).setDestPort(packetDestPort).setSeq(b.iss).setAck(0x00).setDataOffset(0x05).setReserved(0x00).setWindow(b.rWnd).setUrgentPointer(0x00).setOptions(v).setPayload(v1).setRealChecksum(b.sourceAddress, b.destAddress);
  
  int sock = bindSocket(b.sourceAddress);
  if(sock != -1){
    if(sendPacket(sock,b.destAddress, p) != -1){
      b.sUna = p.getSeqNum();
      b.sNxt = p.getSeqNum() + p.payload.size() + 1; //syn consumes 1
      b.retransmit.push_back(p);
      synSent(b,sock);
    }
  }
  
}


