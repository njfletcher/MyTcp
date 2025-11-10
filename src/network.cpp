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

bool bindSocket(uint32_t sourceAddr, int& sRet){
  struct sockaddr_in serv;
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = toAltOrder<uint32_t>(sourceAddr);
  
  int s = socket(AF_INET, SOCK_RAW, TCP_PROTO);	
  if(s < 0){
      return false;
  }
  int mark = 132322;
  if(setsockopt(s,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)) < 0){
    return false;
  }
    
  if(bind(s, (struct sockaddr* ) &serv, sizeof(serv)) != 0){
    return false;
  }
  
  sRet = s;
  return true;

}

bool sendPacket(int sock, uint32_t destAddr, TcpPacket& p){  
  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = toAltOrder<uint32_t>(destAddr);
  
  vector<uint8_t> buffer;
  p.toBuffer(buffer);
  
  #ifdef TEST_NO_SEND
    return true;
  #else
    ssize_t numBytes = sendto(sock, buffer.data(), buffer.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
    if(numBytes < 0){
      return false;
    }
  #endif

  return true;
}


//returns bool representing if there were no errors with actually getting the packet
// goodPacket is a bool that represents whether or not the packet is a valid tcp/ip packet
bool recPacket(int sock, IpPacket& packet, IpPacketCode& packetCode){

  ssize_t numRec = recvfrom(sock,ipBuffer,ipPacketMaxSize,0,nullptr, nullptr);
	
  if(numRec < 0){
    return false;
  }   
    
  packetCode = packet.fromBuffer(ipBuffer, numRec);
  return true;
  
}
	
      	
      	
