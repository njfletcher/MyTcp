#include "network.h"
#include "ipPacket.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <iostream>
#include <arpa/inet.h>
    

using namespace std;

uint8_t ipBuffer[ipPacketMaxSize];

//TODO: look into path mtu discovery.
uint32_t getMtu(uint32_t destAddr){
  return defaultMTU;
}

//MMS_R: maximum transport message that the ip implementation can receive and reassemble.
//assuming for now that ip implementation can reassemble the max ip packet size
uint32_t getMmsR(){
  return ipPacketMaxSize - ipMinHeaderLen;
}

//MMS_S: maximum transport message that the ip implementation can send.
//assuming for now that ip implementation can send the max ip packet size
uint32_t getMmsS(){
  return ipPacketMaxSize - ipMinHeaderLen;

}

NetworkCode bindSocket(uint32_t sourceAddr, int& socket){
  struct sockaddr_in serv;
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = toAltOrder<uint32_t>(sourceAddr);
  
  int s = socket(AF_INET, SOCK_RAW, TCP_PROTO);	
  if(s < 0){
      return NetworkCode::errorFatal;
  }
  int mark = 132322;
  if(setsockopt(s,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)) < 0){
    return NetworkCode::errorFatal;
  }
    
  if(bind(s, (struct sockaddr* ) &serv, sizeof(serv)) != 0){
    return NetworkCode::errorFatal;
  }
  
  socket = s;
  return NetworkCode::success;

}

NetworkCode sendPacket(int sock, uint32_t destAddr, TcpPacket& p){  
  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = toAltOrder<uint32_t>(destAddr);
  
  vector<uint8_t> buffer;
  p.toBuffer(buffer);

  ssize_t numBytes = sendto(sock, buffer.data(), buffer.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
  if(numBytes < 0){
    perror("Cannot send message. ");
    return NetworkCode::errorFatal;
  }
  
  return NetworkCode::success;
}

NetworkCode recPacket(int sock, IpPacket& packet){

  *numBytesInner = 0;
  ssize_t numRec = recvfrom(sock,ipBuffer,ipPacketMaxSize,0,nullptr, nullptr);
	
  if(numRec < 0){
    return NetworkCode::errorFatal;
  }   
	
  IpPacketCode rs = packet.fromBuffer(ipBuffer, numRec);
  if(rs != IpPacketCode::success){
    return NetworkCode::errorNonFatal;
  }
	
  return NetworkCode::success;
}	
      	
      	
      	
      	
      	
      	
      	
      	
