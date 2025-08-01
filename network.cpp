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

//returns socket, or -1 if fail
int bindSocket(uint32_t sourceAddr){
  struct sockaddr_in serv;
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = toAltOrder<uint32_t>(sourceAddr);
  
  int s = socket(AF_INET, SOCK_RAW, TCP_PROTO);	
  if(s < 0){
      perror("Cannot create socket. ");
      return -1;
  }
  int mark = 132322;
  if(setsockopt(s,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)) < 0){
    perror("Cannot mark socket. ");
    return -1;
  }
    
  if(bind(s, (struct sockaddr* ) &serv, sizeof(serv)) != 0){
    perror("Cannot bind socket to server port. ");
    return -1;     
  }
  
  return s;

}

LocalStatus sendPacket(int sock, uint32_t destAddr, TcpPacket& p){  
  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = toAltOrder<uint32_t>(destAddr);
  
  vector<uint8_t> buffer;
  p.toBuffer(buffer);

  ssize_t numBytes = sendto(sock, buffer.data(), buffer.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
  if(numBytes < 0){
    perror("Cannot send message. ");
    return LocalStatus::RawSocket;
  }
  
  return LocalStatus::Success;
}

Status recPacket(int sock, IpPacket& packet){

  *numBytesInner = 0;
  ssize_t numRec = recvfrom(sock,ipBuffer,ipPacketMaxSize,0,nullptr, nullptr);
	
  if(numRec < 0){
    perror("Cannot receive message. ");
    return Status(LocalStatus::RawSocket);
  }   
	
  RemoteStatus rs = packet.fromBuffer(ipBuffer, numRec);
  if(rs != RemoteStatus::Success){
    perror("Bad packet. ");
    return Status(rs);
  }
	
  return Status();
}	
      	
      	
      	
      	
      	
      	
      	
      	
