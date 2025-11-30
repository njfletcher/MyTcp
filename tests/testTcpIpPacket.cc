#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include "../src/ipPacket.h"
#include <iostream>

using namespace std;

namespace tcpIpPacketTests{

TEST(StandardTCPIPPacket, GoodPacketNoOptions){

  int buffSize = IP_MIN_HEADER_LEN + TCP_MIN_HEADER_LEN;
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
  ASSERT_EQ(c  ,  IpPacketCode::SUCCESS);
  EXPECT_EQ(p.getVersion()  ,  0x4);
  EXPECT_EQ(p.getIHL()  ,  0x5);
  EXPECT_EQ(p.getDscp()  ,  0b00101010);
  EXPECT_EQ(p.getEcn()  ,  0b00000011);
  EXPECT_EQ(p.getTotalLength()  ,  0x0028);
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
  
  TcpPacket& tP = p.getTcpPacket();
  EXPECT_EQ(tP.getSrcPort(), 0x1234);
  EXPECT_EQ(tP.getDestPort(), 0x5678);
  EXPECT_EQ(tP.getSeqNum(), 0x12345678);
  EXPECT_EQ(tP.getAckNum() , 0x87654321);
  EXPECT_EQ(tP.getDataOffset() , 0x5);
  EXPECT_EQ(tP.getReserved() , 0x0);
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::CWR));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::ECE));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::URG));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::ACK));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::PSH));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::RST));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::SYN));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::FIN));
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

  int buffSize = IP_MIN_HEADER_LEN + 8 + TCP_MIN_HEADER_LEN + 8;
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
  ASSERT_EQ(c  ,  IpPacketCode::SUCCESS);
  EXPECT_EQ(p.getVersion()  ,  0x4);
  EXPECT_EQ(p.getIHL()  ,  0x7);
  EXPECT_EQ(p.getDscp()  ,  0b00101010);
  EXPECT_EQ(p.getEcn()  ,  0b00000011);
  EXPECT_EQ(p.getTotalLength()  ,  0x0038);
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
  
  vector<IpOption>& ipOptionsList = p.getOptions();
  ASSERT_EQ(ipOptionsList.size()  ,  3);
  IpOption& firstOpt = ipOptionsList[0];
  EXPECT_TRUE(
    (firstOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::TS)) 
    && (firstOpt.getLength()  ==  6) 
    && (firstOpt.getData().size()  ==  4) 
    && (firstOpt.getData()[0] == 0x10) 
    && (firstOpt.getData()[1]  ==  0x20) 
    && (firstOpt.getData()[2]  ==  0x30) 
    && (firstOpt.getData()[3] ==  0x40)
  );
  IpOption& secOpt = ipOptionsList[1];
  EXPECT_TRUE(
    (secOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::NOOP)) 
    && (!secOpt.getHasLength()) 
    && (secOpt.getData().size()  == 0)
  );
  IpOption& thirdOpt = ipOptionsList[2];
  EXPECT_TRUE(
    (thirdOpt.getType()  ==  static_cast<uint8_t>(IpOptionType::EOOL)) 
    && (!thirdOpt.getHasLength()) 
    && (thirdOpt.getData().size()  ==  0)
  );
  
  TcpPacket& tP = p.getTcpPacket();
  EXPECT_EQ(tP.getSrcPort(), 0x1234);
  EXPECT_EQ(tP.getDestPort(), 0x5678);
  EXPECT_EQ(tP.getSeqNum(), 0x12345678);
  EXPECT_EQ(tP.getAckNum() , 0x87654321);
  EXPECT_EQ(tP.getDataOffset() , 0x7);
  EXPECT_EQ(tP.getReserved() , 0x0);
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::CWR));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::ECE));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::URG));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::ACK));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::PSH));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::RST));
  EXPECT_TRUE(tP.getFlag(TcpPacketFlags::SYN));
  EXPECT_FALSE(tP.getFlag(TcpPacketFlags::FIN));
  EXPECT_EQ(tP.getWindow() , 0x1425);
  EXPECT_EQ(tP.getChecksum() , 0x3647);
  EXPECT_EQ(tP.getUrg() , 0x1122);
  
  vector<TcpOption>& tcpOptionsList = tP.getOptions();
  ASSERT_EQ(tcpOptionsList.size()  ,  5);
  TcpOption& fourthOpt = tcpOptionsList[0];
  EXPECT_TRUE(
    (fourthOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::MSS)) 
    && (fourthOpt.getLength()  ==  4) 
    && (fourthOpt.getData().size()  ==  2) 
    && (fourthOpt.getData()[0] == 0x10) 
    && (fourthOpt.getData()[1]  ==  0x01)
  );
  TcpOption& fifthOpt = tcpOptionsList[1];
  EXPECT_TRUE(
    (fifthOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::NOOP)) 
    && (!fifthOpt.getHasLength()) 
    && (fifthOpt.getData().size()  ==  0)
  );
  TcpOption& sixthOpt = tcpOptionsList[2];
  EXPECT_TRUE(
    (sixthOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::NOOP)) 
    && (!sixthOpt.getHasLength()) 
    && (sixthOpt.getData().size()  ==  0)
  );
  TcpOption& seventhOpt = tcpOptionsList[3];
  EXPECT_TRUE(
    (seventhOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::NOOP)) 
    && (!seventhOpt.getHasLength()) 
    && (seventhOpt.getData().size()  ==  0)
  );
  TcpOption& eigthOpt = tcpOptionsList[4];
  EXPECT_TRUE(
    (eigthOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::END)) 
    && (!eigthOpt.getHasLength()) 
    && (eigthOpt.getData().size()  ==  0)
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
}
