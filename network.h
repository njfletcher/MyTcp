#pragma once
#include "packet.h"
#include <vector>
#define TCP_PROTO 6 
 
int sendPacket(uint32_t destAddr, uint32_t sourceAddr, uint16_t destPort, uint16_t sourcePort, TcpPacket& p, IpPacket& packet);

template<typename T>
T toAltOrder(T val);
template<typename T>
void loadBytes(T val, std::vector<uint8_t>& buff);
template<typename T>
T unloadBytes(std::vector<uint8_t>& buff, int startIndex);
