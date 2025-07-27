#pragma once
#include "packet.h"
#include <vector>
#define TCP_PROTO 6 

int bindSocket(uint32_t sourceAddr);
LocalStatus sendPacket(int sock, uint32_t destAddr, TcpPacket& p);
Status recPacket(int sock, IpPacket& packet);
	

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
T unloadBytes(uint8_t* buff, int startIndex){
  T retVal = 0;
  size_t numBytes = sizeof(T);
  for(size_t i = 0; i < numBytes; i++){
    retVal = retVal | (buff[startIndex + i] << (8 * i));
  }
  return retVal;
}
