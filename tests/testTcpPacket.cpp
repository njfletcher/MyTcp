
#include "test.h"
#define TEST_NO_SEND 1
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include <iostream>

int testsPassed = 0;
int totalTests = 0;

void clear(){
  connections.clear();
  idMap.clear();
}

using namespace std;

bool testStandardPacket(){

  cout << "Testing standard tcp packet" << endl;
  
  uint8_t buffer[tcpMinHeaderLen] = { 0x12, 0x34, 
                                   0x56, 0x78, 
                                   0x12, 0x34, 0x56, 0x78,
                                   0x87, 0x65, 0x43, 0x21,
                                   0x50, 
                                   0b10101010, 
                                   0x14, 0x25,
                                   0x36,0x47,
                                   0x11, 0x22
                                 };
      
  TcpPacket p;
  TcpPacketCode c = p.fromBuffer(buffer, tcpMinHeaderLen);
  assert(c == TcpPacketCode::Success, "Packet parse failed")
  assert(p.getSrcPort() == 0x1234, "Wrong source port")
  assert(p.getDestPort() == 0x5678, "Wrong dest port")
  assert(p.getSeqNum() == 0x12345678, "Wrong seq num")
  assert(p.getAckNum() == 0x87654321, "Wrong ack num")
  assert(p.getDataOffset() == 0x5, "Wrong data offset")
  assert(p.getReserved() == 0x0, "Wrong reserved")
  assert(p.getFlag(TcpPacketFlags::cwr), "Wrong cwr flag")
  assert(!p.getFlag(TcpPacketFlags::ece), "Wrong ece flag")
  assert(p.getFlag(TcpPacketFlags::urg), "Wrong urg flag")
  assert(!p.getFlag(TcpPacketFlags::ack), "Wrong ack flag")
  assert(p.getFlag(TcpPacketFlags::psh), "Wrong psh flag")
  assert(!p.getFlag(TcpPacketFlags::rst), "Wrong rst flag")
  assert(p.getFlag(TcpPacketFlags::syn), "Wrong syn flag")
  assert(!p.getFlag(TcpPacketFlags::fin), "Wrong fin flag")
  assert(p.getWindow() == 0x1425, "Wrong window")
  assert(p.getChecksum() == 0x3647, "Wrong checksum")
  assert(p.getUrg() == 0x1122, "Wrong urgent pointer")
  
  vector<uint8_t> buff;
  p.toBuffer(buff);
  assert(buff.size() == tcpMinHeaderLen, "Output buff has wrong size")
  
  bool buffsMatch = true;
  for(int i = 0; i < tcpMinHeaderLen; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  assert(buffsMatch, "Input and Output buffers dont match")
  
  return true;
}


int main(int argc, char** argv){
  test(testStandardPacket())
  cout << testsPassed << " tests passed out of " << totalTests << endl;
  return 0;
}
