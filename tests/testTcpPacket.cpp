
#include "test.h"
#define TEST_NO_SEND 1
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include <iostream>

int testsPassed = 0;
int totalTests = 0;

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


bool testStandardOptionPacket(){

  const int buffSize = tcpMinHeaderLen + 8;
  cout << "Testing standard tcp packet with standard options" << endl;
 
  uint8_t buffer[buffSize] = { 0x12, 0x34, 
                                   0x56, 0x78, 
                                   0x12, 0x34, 0x56, 0x78,
                                   0x87, 0x65, 0x43, 0x21,
                                   0x70, 
                                   0b10101010, 
                                   0x14, 0x25,
                                   0x36,0x47,
                                   0x11, 0x22,
                                   0x02, 0x04, 0x10, 0x01,
                                   0x01,
                                   0x01,
                                   0x01,
                                   0x00
                                 };
      
  TcpPacket p;
  TcpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == TcpPacketCode::Success, "Packet parse failed")
  assert(p.getSrcPort() == 0x1234, "Wrong source port")
  assert(p.getDestPort() == 0x5678, "Wrong dest port")
  assert(p.getSeqNum() == 0x12345678, "Wrong seq num")
  assert(p.getAckNum() == 0x87654321, "Wrong ack num")
  assert(p.getDataOffset() == 0x7, "Wrong data offset")
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
  
  assert(p.optionList.size() == 5, "Incorrect number of options")
  TcpOption& firstOpt = p.optionList[0];
  assert((firstOpt.kind == static_cast<uint8_t>(TcpOptionKind::mss)) && (firstOpt.length == 4) && (firstOpt.data.size() == 2) && (firstOpt.data[0] = 0x10) && (firstOpt.data[1] == 0x01), "First Option incorrect")
  TcpOption& secOpt = p.optionList[1];
  assert((secOpt.kind == static_cast<uint8_t>(TcpOptionKind::noOp)) && (!secOpt.hasLength) && (secOpt.data.size() == 0), "Second Option incorrect")
  TcpOption& thirdOpt = p.optionList[2];
  assert((thirdOpt.kind == static_cast<uint8_t>(TcpOptionKind::noOp)) && (!thirdOpt.hasLength) && (thirdOpt.data.size() == 0), "Third Option incorrect")
  TcpOption& fourthOpt = p.optionList[3];
  assert((fourthOpt.kind == static_cast<uint8_t>(TcpOptionKind::noOp)) && (!fourthOpt.hasLength) && (fourthOpt.data.size() == 0), "Fourth Option incorrect")
  TcpOption& fifthOpt = p.optionList[4];
  assert((fifthOpt.kind == static_cast<uint8_t>(TcpOptionKind::end)) && (!fifthOpt.hasLength) && (fifthOpt.data.size() == 0), "Fifth Option incorrect")
  
  vector<uint8_t> buff;
  p.toBuffer(buff);
  assert(buff.size() == buffSize, "Output buff has wrong size")
  
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

bool testUnimplementedOptionPacket(){

  const int buffSize = tcpMinHeaderLen + 4;
  cout << "Testing standard tcp packet with unimplemented options" << endl;
 
  uint8_t buffer[buffSize] = { 0x12, 0x34, 
                                   0x56, 0x78, 
                                   0x12, 0x34, 0x56, 0x78,
                                   0x87, 0x65, 0x43, 0x21,
                                   0x60, 
                                   0b10101010, 
                                   0x14, 0x25,
                                   0x36,0x47,
                                   0x11, 0x22,
                                   0xFF, 0x03, 0xFF,
                                   0x01
                                 };
      
  TcpPacket p;
  TcpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == TcpPacketCode::Success, "Packet parse failed")
  assert(p.optionList.size() == 2, "Incorrect number of options")
  TcpOption& firstOpt = p.optionList[0];
  assert((firstOpt.kind == 0xFF) && (firstOpt.length == 3) && (firstOpt.data.size() == 1) && (firstOpt.data[0] = 0xFF), "First Option incorrect")
  TcpOption& secOpt = p.optionList[1];
  assert((secOpt.kind == static_cast<uint8_t>(TcpOptionKind::noOp)) && (!secOpt.hasLength) && (secOpt.data.size() == 0), "Second Option incorrect")
 
  vector<uint8_t> buff;
  p.toBuffer(buff);
  assert(buff.size() == buffSize, "Output buff has wrong size")
  
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

bool testEarlyEndOptionPacket(){

  const int buffSize = tcpMinHeaderLen + 4;
  cout << "Testing standard tcp packet with early end option" << endl;
 
  uint8_t buffer[buffSize] = { 0x12, 0x34, 
                                   0x56, 0x78, 
                                   0x12, 0x34, 0x56, 0x78,
                                   0x87, 0x65, 0x43, 0x21,
                                   0x60, 
                                   0b10101010, 
                                   0x14, 0x25,
                                   0x36,0x47,
                                   0x11, 0x22,
                                   0x0, 
                                   0x01, 
                                   0x01,
                                   0x01
                                 };
      
  TcpPacket p;
  TcpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == TcpPacketCode::Success, "Packet parse failed")
  assert(p.optionList.size() == 1, "Incorrect number of options")
  TcpOption& firstOpt = p.optionList[0];
  assert((firstOpt.kind == static_cast<uint8_t>(TcpOptionKind::end)) && (!firstOpt.hasLength), "First Option incorrect")
 
  return true;
}

bool testHeaderOvershootPacket(){

  const int buffSize = tcpMinHeaderLen + 4;
  cout << "Testing packet that overshoots buffer" << endl;
 
  uint8_t buffer[buffSize] = { 0x12, 0x34, 
                                   0x56, 0x78, 
                                   0x12, 0x34, 0x56, 0x78,
                                   0x87, 0x65, 0x43, 0x21,
                                   0xF0, 
                                   0b10101010, 
                                   0x14, 0x25,
                                   0x36,0x47,
                                   0x11, 0x22,
                                   0x0, 
                                   0x01, 
                                   0x01,
                                   0x01
                                 };
      
  TcpPacket p;
  TcpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == TcpPacketCode::Header, "Packet parse should have failed")
 
  return true;
}

bool testOptionOvershootPacket(){

  const int buffSize = tcpMinHeaderLen + 4;
  cout << "Testing packet with option that overshoots data" << endl;
 
  uint8_t buffer[buffSize] = { 0x12, 0x34, 
                                   0x56, 0x78, 
                                   0x12, 0x34, 0x56, 0x78,
                                   0x87, 0x65, 0x43, 0x21,
                                   0x60, 
                                   0b10101010, 
                                   0x14, 0x25,
                                   0x36,0x47,
                                   0x11, 0x22,
                                   0xFF, 0xFF, 0x1
                                 };
      
  TcpPacket p;
  TcpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == TcpPacketCode::Options, "Packet parse should have failed")
 
  return true;
}

int main(int argc, char** argv){
  test(testStandardPacket())
  test(testStandardOptionPacket())
  test(testUnimplementedOptionPacket())
  test(testEarlyEndOptionPacket())
  test(testHeaderOvershootPacket())
  test(testOptionOvershootPacket())
  cout << testsPassed << " tests passed out of " << totalTests << endl;
  return 0;
}
