#include <gtest/gtest.h>
#define TEST_NO_SEND 1
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include "../src/ipPacket.h"
#include <iostream>

using namespace std;

TEST(StandardIPPacket, GoodPacketNoOptions){

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
  ASSERT_TRUE((c  ==  IpPacketCode::Success) || (c  ==  IpPacketCode::Payload));
  EXPECT_EQ(p.getVersion()  ,  0x4);
  EXPECT_EQ(p.getIHL()  ,  0x5);
  EXPECT_EQ(p.getDscp()  ,  0b00101010);
  EXPECT_EQ(p.getEcn()  ,  0b00000011);
  EXPECT_EQ(p.getTotalLength()  ,  0x0014);
  EXPECT_EQ(p.getIdent()  ,  0x4321);
  EXPECT_FALSE(p.getFlag(IpPacketFlags::reserved));
  EXPECT_TRUE(p.getFlag(IpPacketFlags::dontFrag));
  EXPECT_TRUE(p.getFlag(IpPacketFlags::moreFrag));
  EXPECT_EQ(p.getFragOffset()  ,  0b0001110110101010);
  EXPECT_EQ(p.getTtl()  ,  0x12);
  EXPECT_EQ(p.getProto()  ,  0x34);
  EXPECT_EQ(p.getChecksum()  ,  0x5678);
  EXPECT_EQ(p.getSrcAddr()  ,  0x12345678);
  EXPECT_EQ(p.getDestAddr()  ,  0x87654321);
  
  vector<uint8_t> buff;
  p.toBuffer(buff); 
  bool buffsMatch = true;
  for(int i = 0; i < ipMinHeaderLen; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  EXPECT_TRUE(buffsMatch);
}


TEST(StandardIPPacket, GoodPacketDefinedOptions){

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
  ASSERT_TRUE((c  ==  IpPacketCode::Success) || (c  ==  IpPacketCode::Payload));
  EXPECT_EQ(p.getVersion()  ,  0x4);
  EXPECT_EQ(p.getIHL()  ,  0x7);
  EXPECT_EQ(p.getDscp()  ,  0b00101010);
  EXPECT_EQ(p.getEcn()  ,  0b00000011);
  EXPECT_EQ(p.getTotalLength()  ,  0x001C);
  EXPECT_EQ(p.getIdent()  ,  0x4321);
  EXPECT_FALSE(p.getFlag(IpPacketFlags::reserved));
  EXPECT_TRUE(p.getFlag(IpPacketFlags::dontFrag));
  EXPECT_TRUE(p.getFlag(IpPacketFlags::moreFrag));
  EXPECT_EQ(p.getFragOffset()  ,  0b0001110110101010);
  EXPECT_EQ(p.getTtl()  ,  0x12);
  EXPECT_EQ(p.getProto()  ,  0x34);
  EXPECT_EQ(p.getChecksum()  ,  0x5678);
  EXPECT_EQ(p.getSrcAddr()  ,  0x12345678);
  EXPECT_EQ(p.getDestAddr()  ,  0x87654321);
  
  ASSERT_EQ(p.optionList.size()  ,  3);
  IpOption& firstOpt = p.optionList[0];
  EXPECT_TRUE(
    (firstOpt.type  ==  static_cast<uint8_t>(IpOptionType::ts)) 
    && (firstOpt.length  ==  6) 
    && (firstOpt.data.size()  ==  4) 
    && (firstOpt.data[0] == 0x10) 
    && (firstOpt.data[1]  ==  0x20) 
    && (firstOpt.data[2]  ==  0x30) 
    && (firstOpt.data[3] ==  0x40)
  );
  IpOption& secOpt = p.optionList[1];
  EXPECT_TRUE(
    (secOpt.type  ==  static_cast<uint8_t>(IpOptionType::nop)) 
    && (!secOpt.hasLength) 
    && (secOpt.data.size()  == 0)
  );
  IpOption& thirdOpt = p.optionList[2];
  EXPECT_TRUE(
    (thirdOpt.type  ==  static_cast<uint8_t>(IpOptionType::eool)) 
    && (!thirdOpt.hasLength) 
    && (thirdOpt.data.size()  ==  0)
  );
  
  vector<uint8_t> buff;
  p.toBuffer(buff);

  bool buffsMatch = true;
  for(int i = 0; i < buffSize; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  EXPECT_TRUE(buffsMatch);
}

TEST(StandardIPPacket, GoodPacketUndefinedOption){

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
  ASSERT_TRUE((c  ==  IpPacketCode::Success) || (c  ==  IpPacketCode::Payload));
  
  ASSERT_EQ(p.optionList.size()  ,  3);
  IpOption& firstOpt = p.optionList[0];
  EXPECT_TRUE(
    (firstOpt.type  ==  0x3) 
    && (firstOpt.length  ==  6) 
    && (firstOpt.data.size()  ==  4) 
    && (firstOpt.data[0] == 0x10) 
    && (firstOpt.data[1]  ==  0x20) 
    && (firstOpt.data[2]  ==  0x30) 
    && (firstOpt.data[3]  ==  0x40)
  );
  IpOption& secOpt = p.optionList[1];
  EXPECT_TRUE(
    (secOpt.type  ==  static_cast<uint8_t>(IpOptionType::nop)) 
    && (!secOpt.hasLength) 
    && (secOpt.data.size()  ==  0)
  );
  IpOption& thirdOpt = p.optionList[2];
  EXPECT_TRUE(
    (thirdOpt.type  ==  static_cast<uint8_t>(IpOptionType::eool)) 
    && (!thirdOpt.hasLength) 
    && (thirdOpt.data.size()  ==  0)
  );
  
  vector<uint8_t> buff;
  p.toBuffer(buff);

  bool buffsMatch = true;
  for(int i = 0; i < buffSize; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  EXPECT_TRUE(buffsMatch);
}

TEST(StandardIPPacket, GoodPacketEarlyEndOption){

  const int buffSize = ipMinHeaderLen + 4;  
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
  ASSERT_TRUE((c  ==  IpPacketCode::Success) || (c  ==  IpPacketCode::Payload));
  
  ASSERT_EQ(p.optionList.size()  ,  1);
  IpOption& firstOpt = p.optionList[0];
  EXPECT_TRUE(
    (firstOpt.type  ==  static_cast<uint8_t>(IpOptionType::eool)) 
    && (!firstOpt.hasLength) 
    && (firstOpt.data.size() == 0)
  );
  
}

TEST(StandardIPPacket, BadPacketPacketOvershoot){

  const int buffSize = tcpMinHeaderLen + 4;
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
  ASSERT_EQ(c  ,  IpPacketCode::Header);
  
}

TEST(StandardIPPacket, BadPacketOptionOvershoot){

  const int buffSize = tcpMinHeaderLen + 4;
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
  ASSERT_EQ(c  ,  IpPacketCode::Header);
 
}

