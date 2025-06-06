#include "network.h"
#include "packet.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <iostream>
#include <arpa/inet.h>
    

using namespace std;

uint8_t ipBuffer[ipPacketMaxSize];


template<typename T>
T toAltOrder(T val){
  size_t numBytes = sizeof(T);
  T retVal = 0;
  for(size_t i = 0; i < numBytes; i++){
    int shift = 8 * (numBytes -1 - i);
    T currByte = (val & (0xFF << (8 * i))) >> (8 * i);
    retVal = retVal | (currByte << shift);
  }
  return retVal;
}

template<typename T>
void loadBytes(T val, std::vector<uint8_t>& buff){
  size_t numBytes = sizeof(T);
  for(size_t i = 0; i < numBytes; i++){
    uint8_t currByte = ((val & (0xFF << (8 * i))) >> (8 * i)) & 0xff;
    buff.push_back(currByte);
  }

}

//assumes [startIndex, startIndex + wordSize) is valid
template<typename T>
T unloadBytes(std::vector<uint8_t>& buff, int startIndex){
  T retVal = 0;
  size_t numBytes = sizeof(T);
  for(size_t i = 0; i < numBytes; i++){
    retVal = retVal | (buffer[startIndex + i] << (8 * i));
  }
  return retVal;
}

int sendPacket(uint32_t destAddr, uint32_t sourceAddr, uint16_t destPort, uint16_t sourcePort, TcpPacket& p, IpPacket& packet){  
  
  	struct sockaddr_in dest;
	struct sockaddr_in serv;
	int s = socket(AF_INET, SOCK_RAW, TCP_PROTO);
	
	if(s < 0){
		perror("Cannot create socket. ");
		return -1;
	}
		
	dest.sin_family = AF_INET;
        dest.sin_port = toAltOrder<uint16_t>(destPort);
        dest.sin_addr.s_addr = toAltOrder<uint32_t>(destAddr);
        
        serv.sin_family = AF_INET;
        serv.sin_port = toAltOrder<uint16_t>(sourcePort);
        serv.sin_addr.s_addr = toAltOrder<uint32_t>(sourceAddr);
                
	if(bind(s, (struct sockaddr* ) &serv, sizeof(serv)) != 0){
                
                perror("Cannot bind socket to server port. ");
         	return -1;     
        }
        
        vector<uint8_t> buffer;
        p.toBuffer(buffer);
        for(size_t i = 0; i < buffer.size(); i++){
          ipBuffer[i] = buffer[i];
        }
                        
        ssize_t numBytes = sendto(s, ipBuffer, buffer.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
	
	if(numBytes < 0){
		perror("Cannot send message. ");
		return -1;
	}
	
	ssize_t numRec = recvfrom(s,ipBuffer,ipPacketMaxSize,0,nullptr, nullptr);
	
	if(numRec < 0){
		perror("Cannot receive message. ");
		return -1;
	}   
	
	int ret = packet.fromBuffer(ipBuffer, numRec);
	if(ret < 0){
	      perror("Bad packet. ");
	      return -1;
	}
	
	return 0;
}	
      	
      	
