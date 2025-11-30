#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include "../src/ipPacket.h"
#include <iostream>

using namespace std;

namespace ipPacketTests{

TEST(StandardIPPacket, GoodPacketNoOptions){

  uint8_t buffer[IP_MIN_HEADER_LEN] = { 0x45, 
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
  IpPacketCode c = p.fromBuffer(buffer, IP_MIN_HEADER_LEN);
  ASSERT_TRUE((c  ==  IpPacketCode::SUCCESS) || (c  ==  IpPacketCode::PAYLOAD));
  EXPECT_EQ(p.getVersion()  ,  0x4);
  EXPECT_EQ(p.getIHL()  ,  0x5);
  EXPECT_EQ(p.getDscp()  ,  0b00101010);
  EXPECT_EQ(p.getEcn()  ,  0b00000011);
  EXPECT_EQ(p.getTotalLength()  ,  0x0014);
  EXPECT_EQ(p.getIdent()  ,  0x4321);
  EXPECT_FALSE(p.getFlag(IpPacketFlags::RESERVED));
  EXPECT_TRUE(p.getFlag(IpPacketFlags::DONTFRAG));
  EXPECT_TRUE(p.getFlag(IpPacketFlags::MOREFRAG));
  EXPECT_EQ(p.getFragOffset()  ,  0b0001110110101010);
  EXPECT_EQ(p.getTtl()  ,  0x12);
  EXPECT_EQ(p.getProto()  ,  0x34);
  EXPECT_EQ(p.getChecksum()  ,  0x5678);
  EXPECT_EQ(p.getSrcAddr()  ,  0x12345678);
  EXPECT_EQ(p.getDestAddr()  ,  0x87654321);
  
  vector<uint8_t> buff;
  p.toBuffer(buff); 
  bool buffsMatch = true;
  for(int i = 0; i < IP_MIN_HEADER_LEN; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  EXPECT_TRUE(buffsMatch);
}


TEST(StandardIPPacket, GoodPacketDefinedOptions){

  const int buffSize = IP_MIN_HEADER_LEN + 8;
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
  ASSERT_TRUE((c  ==  IpPacketCode::SUCCESS) || (c  ==  IpPacketCode::PAYLOAD));
  EXPECT_EQ(p.getVersion()  ,  0x4);
  EXPECT_EQ(p.getIHL()  ,  0x7);
  EXPECT_EQ(p.getDscp()  ,  0b00101010);
  EXPECT_EQ(p.getEcn()  ,  0b00000011);
  EXPECT_EQ(p.getTotalLength()  ,  0x001C);
  EXPECT_EQ(p.getIdent()  ,  0x4321);
  EXPECT_FALSE(p.getFlag(IpPacketFlags::RESERVED));
  EXPECT_TRUE(p.getFlag(IpPacketFlags::DONTFRAG));
  EXPECT_TRUE(p.getFlag(IpPacketFlags::MOREFRAG));
  EXPECT_EQ(p.getFragOffset()  ,  0b0001110110101010);
  EXPECT_EQ(p.getTtl()  ,  0x12);
  EXPECT_EQ(p.getProto()  ,  0x34);
  EXPECT_EQ(p.getChecksum()  ,  0x5678);
  EXPECT_EQ(p.getSrcAddr()  ,  0x12345678);
  EXPECT_EQ(p.getDestAddr()  ,  0x87654321);
  
  vector<IpOption>& optionsList = p.getOptions();
  ASSERT_EQ(optionsList.size()  ,  3);
  IpOption& firstOpt = optionsList[0];
  EXPECT_TRUE(
    (firstOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::TS)) 
    && (firstOpt.getLength()  ==  6) 
    && (firstOpt.getData().size()  ==  4) 
    && (firstOpt.getData()[0] == 0x10) 
    && (firstOpt.getData()[1]  ==  0x20) 
    && (firstOpt.getData()[2]  ==  0x30) 
    && (firstOpt.getData()[3] ==  0x40)
  );
  IpOption& secOpt = optionsList[1];
  EXPECT_TRUE(
    (secOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::NOOP)) 
    && (!secOpt.getHasLength()) 
    && (secOpt.getData().size()  == 0)
  );
  IpOption& thirdOpt = optionsList[2];
  EXPECT_TRUE(
    (thirdOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::EOOL)) 
    && (!thirdOpt.getHasLength()) 
    && (thirdOpt.getData().size()  ==  0)
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

  const int buffSize = IP_MIN_HEADER_LEN + 8;
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
  ASSERT_TRUE((c  ==  IpPacketCode::SUCCESS) || (c  ==  IpPacketCode::PAYLOAD));
  
  vector<IpOption>& optionsList = p.getOptions();
  ASSERT_EQ(optionsList.size()  ,  3);
  IpOption& firstOpt = optionsList[0];
  EXPECT_TRUE(
    (firstOpt.getType()  ==  0x3) 
    && (firstOpt.getLength()  ==  6) 
    && (firstOpt.getData().size()  ==  4) 
    && (firstOpt.getData()[0] == 0x10) 
    && (firstOpt.getData()[1]  ==  0x20) 
    && (firstOpt.getData()[2]  ==  0x30) 
    && (firstOpt.getData()[3]  ==  0x40)
  );
  IpOption& secOpt = optionsList[1];
  EXPECT_TRUE(
    (secOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::NOOP)) 
    && (!secOpt.getHasLength()) 
    && (secOpt.getData().size()  ==  0)
  );
  IpOption& thirdOpt = optionsList[2];
  EXPECT_TRUE(
    (thirdOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::EOOL)) 
    && (!thirdOpt.getHasLength()) 
    && (thirdOpt.getData().size()  ==  0)
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

  const int buffSize = IP_MIN_HEADER_LEN + 4;  
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
  ASSERT_TRUE((c  ==  IpPacketCode::SUCCESS) || (c  ==  IpPacketCode::PAYLOAD));
  
  vector<IpOption>& optionsList = p.getOptions();
  ASSERT_EQ(optionsList.size()  ,  1);
  IpOption& firstOpt = optionsList[0];
  EXPECT_TRUE(
    (firstOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::EOOL)) 
    && (!firstOpt.getHasLength()) 
    && (firstOpt.getData().size() == 0)
  );
  
}

TEST(StandardIPPacket, BadPacketPacketOvershoot){

  const int buffSize = IP_MIN_HEADER_LEN + 4;
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
  ASSERT_EQ(c  ,  IpPacketCode::HEADER);
  
}

TEST(StandardIPPacket, BadPacketOptionOvershoot){

  const int buffSize = IP_MIN_HEADER_LEN + 4;
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
  ASSERT_EQ(c  ,  IpPacketCode::HEADER);
 
}
}
