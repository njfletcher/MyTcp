#pragma once
#include "packet.h"
#define TCP_PROTO 6 
 
int sendPacket(char* destAddr, TcpPacket& p, IpPacket& packet);
