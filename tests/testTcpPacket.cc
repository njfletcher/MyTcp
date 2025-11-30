#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/tcpPacket.h"
#include <iostream>

using namespace std;

namespace tcpPacketTests{

TEST(StandardTCPPacket, GoodPacketNoOptions){

  uint8_t buffer[TCP_MIN_HEADER_LEN] = { 0x12, 0x34, 
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
  TcpPacketCode c = p.fromBuffer(buffer, TCP_MIN_HEADER_LEN);
  ASSERT_EQ(c, TcpPacketCode::SUCCESS);
  EXPECT_EQ(p.getSrcPort(), 0x1234);
  EXPECT_EQ(p.getDestPort(), 0x5678);
  EXPECT_EQ(p.getSeqNum(), 0x12345678);
  EXPECT_EQ(p.getAckNum() , 0x87654321);
  EXPECT_EQ(p.getDataOffset() , 0x5);
  EXPECT_EQ(p.getReserved() , 0x0);
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::CWR));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::ECE));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::URG));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::ACK));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::PSH));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::RST));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::SYN));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::FIN));
  EXPECT_EQ(p.getWindow() , 0x1425);
  EXPECT_EQ(p.getChecksum() , 0x3647);
  EXPECT_EQ(p.getUrg() , 0x1122);
  
  vector<uint8_t> buff;
  p.toBuffer(buff);
  ASSERT_EQ(buff.size(), TCP_MIN_HEADER_LEN);
  
  bool buffsMatch = true;
  for(int i = 0; i < TCP_MIN_HEADER_LEN; i++){
    if(buff[i] != buffer[i]){
      buffsMatch = false;
      break;
    }
  }
  EXPECT_TRUE(buffsMatch);
}


TEST(StandardTCPPacket, GoodPacketDefinedOptions){

  const int buffSize = TCP_MIN_HEADER_LEN + 8;
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
  ASSERT_EQ(c, TcpPacketCode::SUCCESS);
  EXPECT_EQ(p.getSrcPort()  ,  0x1234);
  EXPECT_EQ(p.getDestPort()  ,  0x5678);
  EXPECT_EQ(p.getSeqNum()  ,  0x12345678);
  EXPECT_EQ(p.getAckNum()  ,  0x87654321);
  EXPECT_EQ(p.getDataOffset()  ,  0x7);
  EXPECT_EQ(p.getReserved()  ,  0x0);
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::CWR));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::ECE));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::URG));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::ACK));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::PSH)); 
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::RST));
  EXPECT_TRUE(p.getFlag(TcpPacketFlags::SYN));
  EXPECT_FALSE(p.getFlag(TcpPacketFlags::FIN));
  EXPECT_EQ(p.getWindow()  ,  0x1425);
  EXPECT_EQ(p.getChecksum()  ,  0x3647);
  EXPECT_EQ(p.getUrg()  ,  0x1122);
  
  vector<TcpOption>& optionsList = p.getOptions();
  ASSERT_EQ(optionsList.size()  ,  5);
  TcpOption& firstOpt = optionsList[0];
  EXPECT_TRUE(
    (firstOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::MSS)) 
    && (firstOpt.getLength()  ==  4) 
    && (firstOpt.getData().size()  ==  2) 
    && (firstOpt.getData()[0] == 0x10) 
    && (firstOpt.getData()[1]  ==  0x01)
  );
  TcpOption& secOpt = optionsList[1];
  EXPECT_TRUE(
    (secOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::NOOP)) 
    && (!secOpt.getHasLength()) 
    && (secOpt.getData().size()  ==  0)
  );
  TcpOption& thirdOpt = optionsList[2];
  EXPECT_TRUE(
    (thirdOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::NOOP)) 
    && (!thirdOpt.getHasLength()) 
    && (thirdOpt.getData().size()  ==  0)
  );
  TcpOption& fourthOpt = optionsList[3];
  EXPECT_TRUE(
    (fourthOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::NOOP)) 
    && (!fourthOpt.getHasLength()) 
    && (fourthOpt.getData().size()  ==  0)
  );
  TcpOption& fifthOpt = optionsList[4];
  EXPECT_TRUE(
    (fifthOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::END)) 
    && (!fifthOpt.getHasLength()) 
    && (fifthOpt.getData().size()  ==  0)
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

  const int buffSize = TCP_MIN_HEADER_LEN + 4;
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
  ASSERT_EQ(c  ,  TcpPacketCode::SUCCESS);
  
  vector<TcpOption>& optionsList = p.getOptions();
  ASSERT_EQ(optionsList.size()  ,  2);
  TcpOption& firstOpt = optionsList[0];
  EXPECT_TRUE(
    (firstOpt.getKind()  ==  0xFF) 
    && (firstOpt.getLength()  ==  3) 
    && (firstOpt.getData().size()  ==  1) 
    && (firstOpt.getData()[0] == 0xFF)
  );
  TcpOption& secOpt = optionsList[1];
  EXPECT_TRUE(
    (secOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::NOOP)) 
    && (!secOpt.getHasLength()) 
    && (secOpt.getData().size()  ==  0)
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

  const int buffSize = TCP_MIN_HEADER_LEN + 4;
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
  ASSERT_EQ(c  ,  TcpPacketCode::SUCCESS);
  
  vector<TcpOption>& optionsList = p.getOptions();
  ASSERT_EQ(optionsList.size()  ,  1);
  TcpOption& firstOpt = optionsList[0];
  EXPECT_TRUE(
    (firstOpt.getKind()  ==  static_cast<uint8_t>(TcpOptionKind::END)) 
    && (!firstOpt.getHasLength())
  );
}

TEST(StandardTCPPacket, BadPacketPacketOvershoot){

  const int buffSize = TCP_MIN_HEADER_LEN + 4;
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
  ASSERT_EQ(c  ,  TcpPacketCode::HEADER);
}

TEST(StandardTCPPacket, BadPacketOptionOvershoot){

  const int buffSize = TCP_MIN_HEADER_LEN + 4;
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
  ASSERT_EQ(c  ,  TcpPacketCode::OPTIONS);
}
}
