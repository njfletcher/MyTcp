#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include "../src/ipPacket.h"
#include <iostream>

using namespace std;

TEST(StandardTCPIPPacket, GoodPacketNoOptions){

  int buffSize = ipMinHeaderLen + tcpMinHeaderLen;
  uint8_t buffer[buffSize] = { 0x45, 
                                      0b10101011, 
                                   0x00, 0x28, 
                                   0x43, 0x21, 
                                   0b01111101, 0b10101010,
                                   0x12,
                                   0x34,
                                   0x56,0x78,
                                   0x12,0x34,0x56,0x78,
                                   0x87,0x65,0x43,0x21, 
                                   
                                   0x12, 0x34, 
                                   0x56, 0x78, 
                                   0x12, 0x34, 0x56, 0x78,
                                   0x87, 0x65, 0x43, 0x21,
                                   0x50, 
                                   0b10101010, 
                                   0x14, 0x25,
                                   0x36,0x47,
                                   0x11, 0x22
                                   
                                 };
      
  IpPacket p;
  IpPacketCode c = p.fromBuffer(buffer, buffSize);
  ASSERT_EQ(c  ,  IpPacketCode::Success);
  EXPECT_EQ(p.getVersion()  ,  0x4);
  EXPECT_EQ(p.getIHL()  ,  0x5);
  EXPECT_EQ(p.getDscp()  ,  0b00101010);
  EXPECT_EQ(p.getEcn()  ,  0b00000011);
  EXPECT_EQ(p.getTotalLength()  ,  0x0028);
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
  
  TcpPacket& tP = p.tcpPacket;
  EXPECT_EQ(tP.getSrcPort(), 0x1234);
  EXPECT_EQ(tP.getDestPort(), 0x5678);
  EXPECT_EQ(tP.getSeqNum(), 0x12345678);
  EXPECT_EQ(tP.getAckNum() , 0x87654321);
  EXPECT_EQ(tP.getDataOffset() , 0x5);
  EXPECT_EQ(tP.getReserved() , 0x0);
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::cwr));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::ece));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::urg));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::ack));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::psh));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::rst));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::syn));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::fin));
  EXPECT_EQ(tP.getWindow() , 0x1425);
  EXPECT_EQ(tP.getChecksum() , 0x3647);
  EXPECT_EQ(tP.getUrg() , 0x1122);
  
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

TEST(StandardTCPIPPacket, GoodPacketDefinedOptions){

  int buffSize = ipMinHeaderLen + 8 + tcpMinHeaderLen + 8;
  uint8_t buffer[buffSize] = { 0x47, 
                                      0b10101011, 
                                   0x00, 0x38, 
                                   0x43, 0x21, 
                                   0b01111101, 0b10101010,
                                   0x12,
                                   0x34,
                                   0x56,0x78,
                                   0x12,0x34,0x56,0x78,
                                   0x87,0x65,0x43,0x21, 
                                   0x44, 0x6, 0x10,0x20,0x30,0x40,
                                   0x1,
                                   0x0,
                                   
                                   0x12, 0x34, 
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
      
  IpPacket p;
  IpPacketCode c = p.fromBuffer(buffer, buffSize);
  ASSERT_EQ(c  ,  IpPacketCode::Success);
  EXPECT_EQ(p.getVersion()  ,  0x4);
  EXPECT_EQ(p.getIHL()  ,  0x7);
  EXPECT_EQ(p.getDscp()  ,  0b00101010);
  EXPECT_EQ(p.getEcn()  ,  0b00000011);
  EXPECT_EQ(p.getTotalLength()  ,  0x0038);
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
  
  TcpPacket& tP = p.tcpPacket;
  EXPECT_EQ(tP.getSrcPort(), 0x1234);
  EXPECT_EQ(tP.getDestPort(), 0x5678);
  EXPECT_EQ(tP.getSeqNum(), 0x12345678);
  EXPECT_EQ(tP.getAckNum() , 0x87654321);
  EXPECT_EQ(tP.getDataOffset() , 0x7);
  EXPECT_EQ(tP.getReserved() , 0x0);
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::cwr));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::ece));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::urg));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::ack));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::psh));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::rst));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::syn));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::fin));
  EXPECT_EQ(tP.getWindow() , 0x1425);
  EXPECT_EQ(tP.getChecksum() , 0x3647);
  EXPECT_EQ(tP.getUrg() , 0x1122);
  
  ASSERT_EQ(tP.optionList.size()  ,  5);
  TcpOption& fourthOpt = tP.optionList[0];
  EXPECT_TRUE(
    (fourthOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::mss)) 
    && (fourthOpt.length  ==  4) 
    && (fourthOpt.data.size()  ==  2) 
    && (fourthOpt.data[0] == 0x10) 
    && (fourthOpt.data[1]  ==  0x01)
  );
  TcpOption& fifthOpt = tP.optionList[1];
  EXPECT_TRUE(
    (fifthOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::noOp)) 
    && (!fifthOpt.hasLength) 
    && (fifthOpt.data.size()  ==  0)
  );
  TcpOption& sixthOpt = tP.optionList[2];
  EXPECT_TRUE(
    (sixthOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::noOp)) 
    && (!sixthOpt.hasLength) 
    && (sixthOpt.data.size()  ==  0)
  );
  TcpOption& seventhOpt = tP.optionList[3];
  EXPECT_TRUE(
    (seventhOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::noOp)) 
    && (!seventhOpt.hasLength) 
    && (seventhOpt.data.size()  ==  0)
  );
  TcpOption& eigthOpt = tP.optionList[4];
  EXPECT_TRUE(
    (eigthOpt.kind  ==  static_cast<uint8_t>(TcpOptionKind::end)) 
    && (!eigthOpt.hasLength) 
    && (eigthOpt.data.size()  ==  0)
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

