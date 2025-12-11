#pragma once
#include "../src/tcpPacket.h"

const int TEST_APP_ID = 0;
const int TEST_SOCKET = 0;
const int TEST_CONN_ID = 1;
const int TEST_EVENT_ID = 1;
const unsigned int TEST_LOC_IP = 1;
const unsigned int TEST_LOC_PORT = 1;
const unsigned int TEST_REM_IP = 1;
const unsigned int TEST_REM_PORT = 1;

extern std::vector<TcpPacket> interceptedPackets;

