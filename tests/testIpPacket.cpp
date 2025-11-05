
#include "test.h"
#define TEST_NO_SEND 1
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include "../src/ipPacket.h"
#include <iostream>

int testsPassed = 0;
int totalTests = 0;

using namespace std;

bool testStandardPacket(){

  cout << "Testing standard ip packet" << endl;
  
  uint8_t buffer[ipMinHeaderLen] = { 0x45, 
                                      0b10101011, 
                                   0x00, 0x14, 
                                   0x43, 0x21, 
                                   0b01111101, 0b10101010,
                                   0x12,
                                   0x34,
                                   0x56,0x78,
                                   0x12,0x34,0x56,0x78,
                                   0x87,0x65,0x43,0x21
                                   
                                   
                                 };
      
  IpPacket p;
  IpPacketCode c = p.fromBuffer(buffer, ipMinHeaderLen);
  assert(c == IpPacketCode::Success || c == IpPacketCode::Payload, "Packet parse failed")
  assert(p.getVersion() == 0x4, "Wrong version")
  assert(p.getIHL() == 0x5, "Wrong header len")
  assert(p.getDscp() == 0b00101010, "Wrong dscp")
  assert(p.getEcn() == 0b00000011, "Wrong ecn")
  assert(p.getTotalLength() == 0x0014, "Wrong total length")
  assert(p.getIdent() == 0x4321, "Wrong identification")
  assert(!p.getFlag(IpPacketFlags::reserved), "Wrong res flag")
  assert(p.getFlag(IpPacketFlags::dontFrag), "Wrong dont frag flag")
  assert(p.getFlag(IpPacketFlags::moreFrag), "Wrong more frag flag")
  assert(p.getFragOffset() == 0b0001110110101010, "Wrong frag offset")
  assert(p.getTtl() == 0x12, "Wrong ttl")
  assert(p.getProto() == 0x34, "Wrong protocol")
  assert(p.getChecksum() == 0x5678, "Wrong checksum")
  assert(p.getSrcAddr() == 0x12345678, "Wrong src addr")
  assert(p.getDestAddr() == 0x87654321, "Wrong dest addr")
  
  vector<uint8_t> buff;
  p.toBuffer(buff); 
  bool buffsMatch = true;
  for(int i = 0; i < ipMinHeaderLen; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  assert(buffsMatch, "Input and Output buffers dont match")
  
  return true;
}


bool testStandardOptionPacket(){

  cout << "Testing standard option ip packet" << endl;
  const int buffSize = ipMinHeaderLen + 8;
  uint8_t buffer[buffSize] = { 0x47, 
                                      0b10101011, 
                                   0x00, 0x1C, 
                                   0x43, 0x21, 
                                   0b01111101, 0b10101010,
                                   0x12,
                                   0x34,
                                   0x56,0x78,
                                   0x12,0x34,0x56,0x78,
                                   0x87,0x65,0x43,0x21,
                                   0x44, 0x6, 0x10,0x20,0x30,0x40,
                                   0x1,
                                   0x0
                                 };
      
  IpPacket p;
  IpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == IpPacketCode::Success || c == IpPacketCode::Payload, "Packet parse failed")
  assert(p.getVersion() == 0x4, "Wrong version")
  assert(p.getIHL() == 0x7, "Wrong header len")
  assert(p.getDscp() == 0b00101010, "Wrong dscp")
  assert(p.getEcn() == 0b00000011, "Wrong ecn")
  assert(p.getTotalLength() == 0x001C, "Wrong total length")
  assert(p.getIdent() == 0x4321, "Wrong identification")
  assert(!p.getFlag(IpPacketFlags::reserved), "Wrong res flag")
  assert(p.getFlag(IpPacketFlags::dontFrag), "Wrong dont frag flag")
  assert(p.getFlag(IpPacketFlags::moreFrag), "Wrong more frag flag")
  assert(p.getFragOffset() == 0b0001110110101010, "Wrong frag offset")
  assert(p.getTtl() == 0x12, "Wrong ttl")
  assert(p.getProto() == 0x34, "Wrong protocol")
  assert(p.getChecksum() == 0x5678, "Wrong checksum")
  assert(p.getSrcAddr() == 0x12345678, "Wrong src addr")
  assert(p.getDestAddr() == 0x87654321, "Wrong dest addr")
  
  assert(p.optionList.size() == 3, "Incorrect number of options")
  IpOption& firstOpt = p.optionList[0];
  assert((firstOpt.type == static_cast<uint8_t>(IpOptionType::ts)) && (firstOpt.length == 6) && (firstOpt.data.size() == 4) && (firstOpt.data[0] = 0x10) && (firstOpt.data[1] == 0x20) && (firstOpt.data[2] == 0x30) && (firstOpt.data[3] == 0x40), "First Option incorrect")
  IpOption& secOpt = p.optionList[1];
  assert((secOpt.type == static_cast<uint8_t>(IpOptionType::nop)) && (!secOpt.hasLength) && (secOpt.data.size() == 0), "Second Option incorrect")
  IpOption& thirdOpt = p.optionList[2];
  assert((thirdOpt.type == static_cast<uint8_t>(IpOptionType::eool)) && (!thirdOpt.hasLength) && (thirdOpt.data.size() == 0), "Third Option incorrect")
  
  vector<uint8_t> buff;
  p.toBuffer(buff);

  bool buffsMatch = true;
  for(int i = 0; i < buffSize; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  assert(buffsMatch, "Input and Output buffers dont match")
  
  return true;
}

bool testUnimplementedOptionPacket(){


  cout << "Testing ip packet with unimplemented option" << endl;
  const int buffSize = ipMinHeaderLen + 8;
  uint8_t buffer[buffSize] = { 0x47, 
                                      0b10101011, 
                                   0x00, 0x1C, 
                                   0x43, 0x21, 
                                   0b01111101, 0b10101010,
                                   0x12,
                                   0x34,
                                   0x56,0x78,
                                   0x12,0x34,0x56,0x78,
                                   0x87,0x65,0x43,0x21,
                                   0x3, 0x6, 0x10,0x20,0x30,0x40,
                                   0x1,
                                   0x0
                                 };
      
  IpPacket p;
  IpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == IpPacketCode::Success || c == IpPacketCode::Payload, "Packet parse failed")
  
  assert(p.optionList.size() == 3, "Incorrect number of options")
  IpOption& firstOpt = p.optionList[0];
  assert((firstOpt.type == 0x3) && (firstOpt.length == 6) && (firstOpt.data.size() == 4) && (firstOpt.data[0] = 0x10) && (firstOpt.data[1] == 0x20) && (firstOpt.data[2] == 0x30) && (firstOpt.data[3] == 0x40), "First Option incorrect")
  IpOption& secOpt = p.optionList[1];
  assert((secOpt.type == static_cast<uint8_t>(IpOptionType::nop)) && (!secOpt.hasLength) && (secOpt.data.size() == 0), "Second Option incorrect")
  IpOption& thirdOpt = p.optionList[2];
  assert((thirdOpt.type == static_cast<uint8_t>(IpOptionType::eool)) && (!thirdOpt.hasLength) && (thirdOpt.data.size() == 0), "Third Option incorrect")
  
  vector<uint8_t> buff;
  p.toBuffer(buff);

  bool buffsMatch = true;
  for(int i = 0; i < buffSize; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  assert(buffsMatch, "Input and Output buffers dont match")
  
  return true;
}

bool testEarlyEndOptionPacket(){

  const int buffSize = ipMinHeaderLen + 4;
  cout << "Testing standard ip packet with early end option" << endl;
  
  uint8_t buffer[buffSize] = { 0x46, 
                                      0b10101011, 
                                   0x00, 0x18, 
                                   0x43, 0x21, 
                                   0b01111101, 0b10101010,
                                   0x12,
                                   0x34,
                                   0x56,0x78,
                                   0x12,0x34,0x56,0x78,
                                   0x87,0x65,0x43,0x21,
                                   0x0,
                                   0x1,
                                   0x1,
                                   0x0
                                 };
      
  IpPacket p;
  IpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == IpPacketCode::Success || c == IpPacketCode::Payload, "Packet parse failed")
  
  assert(p.optionList.size() == 1, "Incorrect number of options")
  IpOption& firstOpt = p.optionList[0];
  assert((firstOpt.type == static_cast<uint8_t>(IpOptionType::eool)) && (!firstOpt.hasLength) && (firstOpt.data.size() == 0), "First Option incorrect")
  
  return true;
}

bool testHeaderOvershootPacket(){

  const int buffSize = tcpMinHeaderLen + 4;
  cout << "Testing packet that overshoots buffer" << endl;
 
  uint8_t buffer[buffSize] = { 0x4F, 
                                      0b10101011, 
                                   0x00, 0x18, 
                                   0x43, 0x21, 
                                   0b01111101, 0b10101010,
                                   0x12,
                                   0x34,
                                   0x56,0x78,
                                   0x12,0x34,0x56,0x78,
                                   0x87,0x65,0x43,0x21,
                                   0x0,
                                   0x1,
                                   0x1,
                                   0x0
                                 };
      
  IpPacket p;
  IpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == IpPacketCode::Header, "Packet parse should have failed")
 
  return true;
}

bool testOptionOvershootPacket(){

  const int buffSize = tcpMinHeaderLen + 4;
  cout << "Testing packet with option that overshoots data" << endl;
 
  uint8_t buffer[buffSize] = { 0x46, 
                                      0b10101011, 
                                   0x00, 0x18, 
                                   0x43, 0x21, 
                                   0b01111101, 0b10101010,
                                   0x12,
                                   0x34,
                                   0x56,0x78,
                                   0x12,0x34,0x56,0x78,
                                   0x87,0x65,0x43,0x21,
                                   0x44, 0xFF, 0x1, 0x0
                                 };
      
  IpPacket p;
  IpPacketCode c = p.fromBuffer(buffer, buffSize);
  assert(c == IpPacketCode::Header, "Packet parse should have failed")
 
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
