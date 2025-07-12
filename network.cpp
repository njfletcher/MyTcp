#include "network.h"
#include "packet.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <iostream>
#include <arpa/inet.h>
    

using namespace std;

uint8_t ipBuffer[ipPacketMaxSize];

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
  for(size_t i = 0; i < buffer.size(); i++){
    ipBuffer[i] = buffer[i];
  }
  ssize_t numBytes = sendto(sock, ipBuffer, buffer.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
  if(numBytes < 0){
    perror("Cannot send message. ");
    return LocalStatus::RawSocket;
  }
  
  return LocalStatus::Success;
}

Status recPacket(int sock, IpPacket& packet){

  ssize_t numRec = recvfrom(sock,ipBuffer,ipPacketMaxSize,0,nullptr, nullptr);
	
  if(numRec < 0){
    perror("Cannot receive message. ");
    return Status(LocalStatus::RawSocket);
  }   
	
  RemoteStatus rs = packet.fromBuffer(ipBuffer, numRec);
  if(ret < 0){
    perror("Bad packet. ");
    return Status(rs);
  }
	
  return Status();
}	
      	
      	
      	
      	
      	
      	
      	
      	
