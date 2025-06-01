#pragma once
#include "packet.h"
#define TCP_PROTO 6 
 
int sendPacket(uint32_t destAddr, uint32_t sourceAddr, uint16_t destPort, uint16_t sourcePort, TcpPacket& p, IpPacket& packet);
