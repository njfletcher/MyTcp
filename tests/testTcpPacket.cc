#include <gtest/gtest.h>
#define TEST_NO_SEND 1
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include <iostream>

using namespace std;

TEST(StandardTCPPacket, GoodPacketNoOptions){

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
  ASSERT_EQ(c, TcpPacketCode::Success);
  EXPECT_EQ(p.getSrcPort(), 0x1234);
  EXPECT_EQ(p.getDestPort(), 0x5678);
  EXPECT_EQ(p.getSeqNum(), 0x12345678);
  EXPECT_EQ(p.getAckNum() , 0x87654321);
  EXPECT_EQ(p.getDataOffset() , 0x5);
  EXPECT_EQ(p.getReserved() , 0x0);
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::cwr));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::ece));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::urg));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::ack));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::psh));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::rst));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::syn));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::fin));
  EXPECT_EQ(p.getWindow() , 0x1425);
  EXPECT_EQ(p.getChecksum() , 0x3647);
  EXPECT_EQ(p.getUrg() , 0x1122);
  
  vector<uint8_t> buff;
  p.toBuffer(buff);
  ASSERT_EQ(buff.size(), tcpMinHeaderLen);
  
  bool buffsMatch = true;
  for(int i = 0; i < tcpMinHeaderLen; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  EXPECT_TRUE(buffsMatch);
}


TEST(StandardTCPPacket, GoodPacketDefinedOptions){

  const int buffSize = tcpMinHeaderLen + 8;
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
  ASSERT_EQ(c, TcpPacketCode::Success);
  EXPECT_EQ(p.getSrcPort()  ,  0x1234);
  EXPECT_EQ(p.getDestPort()  ,  0x5678);
  EXPECT_EQ(p.getSeqNum()  ,  0x12345678);
  EXPECT_EQ(p.getAckNum()  ,  0x87654321);
  EXPECT_EQ(p.getDataOffset()  ,  0x7);
  EXPECT_EQ(p.getReserved()  ,  0x0);
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::cwr));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::ece));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::urg));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::ack));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::psh)); 
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::rst));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::syn));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::fin));
  EXPECT_EQ(p.getWindow()  ,  0x1425);
  EXPECT_EQ(p.getChecksum()  ,  0x3647);
  EXPECT_EQ(p.getUrg()  ,  0x1122);
  
  EXPECT_EQ(p.optionList.size()  ,  5);
  TcpOption& firstOpt = p.optionList[0];
  EXPECT_TRUE(
    (firstOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::mss)) 
    && (firstOpt.length  ==  4) 
    && (firstOpt.data.size()  ==  2) 
    && (firstOpt.data[0] == 0x10) 
    && (firstOpt.data[1]  ==  0x01)
  );
  TcpOption& secOpt = p.optionList[1];
  EXPECT_TRUE(
    (secOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::noOp)) 
    && (!secOpt.hasLength) 
    && (secOpt.data.size()  ==  0)
  );
  TcpOption& thirdOpt = p.optionList[2];
  EXPECT_TRUE(
    (thirdOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::noOp)) 
    && (!thirdOpt.hasLength) 
    && (thirdOpt.data.size()  ==  0)
  );
  TcpOption& fourthOpt = p.optionList[3];
  EXPECT_TRUE(
    (fourthOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::noOp)) 
    && (!fourthOpt.hasLength) 
    && (fourthOpt.data.size()  ==  0)
  );
  TcpOption& fifthOpt = p.optionList[4];
  EXPECT_TRUE(
    (fifthOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::end)) 
    && (!fifthOpt.hasLength) 
    && (fifthOpt.data.size()  ==  0)
  );
  
  vector<uint8_t> buff;
  p.toBuffer(buff);
  EXPECT_EQ(buff.size()  ,  buffSize);
  
  bool buffsMatch = true;
  for(int i = 0; i < buffSize; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  EXPECT_TRUE(buffsMatch);
}

TEST(StandardTCPPacket, GoodPacketUndefinedOptions){

  const int buffSize = tcpMinHeaderLen + 4;
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
  ASSERT_EQ(c  ,  TcpPacketCode::Success);
  EXPECT_EQ(p.optionList.size()  ,  2);
  TcpOption& firstOpt = p.optionList[0];
  EXPECT_TRUE(
    (firstOpt.kind  ==  0xFF) 
    && (firstOpt.length  ==  3) 
    && (firstOpt.data.size()  ==  1) 
    && (firstOpt.data[0] == 0xFF)
  );
  TcpOption& secOpt = p.optionList[1];
  EXPECT_TRUE(
    (secOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::noOp)) 
    && (!secOpt.hasLength) 
    && (secOpt.data.size()  ==  0)
  );
 
  vector<uint8_t> buff;
  p.toBuffer(buff);
  EXPECT_EQ(buff.size()  ,  buffSize);
  
  bool buffsMatch = true;
  for(int i = 0; i < buffSize; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  EXPECT_TRUE(buffsMatch);
}

TEST(StandardTCPPacket, GoodPacketEarlyEndOption){

  const int buffSize = tcpMinHeaderLen + 4;
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
  ASSERT_EQ(c  ,  TcpPacketCode::Success);
  EXPECT_EQ(p.optionList.size()  ,  1);
  TcpOption& firstOpt = p.optionList[0];
  EXPECT_TRUE(
    (firstOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::end)) 
    && (!firstOpt.hasLength)
  );
}

TEST(StandardTCPPacket, BadPacketPacketOvershoot){

  const int buffSize = tcpMinHeaderLen + 4;
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
  ASSERT_EQ(c  ,  TcpPacketCode::Header);
}

TEST(StandardTCPPacket, BadPacketOptionOvershoot){

  const int buffSize = tcpMinHeaderLen + 4;
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
  ASSERT_EQ(c  ,  TcpPacketCode::Options);
}

