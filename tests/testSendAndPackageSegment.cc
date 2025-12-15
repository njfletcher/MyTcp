#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/driver.h"
#include "testingUtil.h"
#include <iostream>

using namespace std;

namespace sendAndPackageSegmentTests{

class SendAndPackageSegmentFixture : public testing::Test{

  void TearDown() override{
    interceptedPackets.clear();
  }
};

TEST_F(SendAndPackageSegmentFixture, SendSimple){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    uint32_t segSize = 50;
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    std::deque<uint8_t> dummyMsg(segSize);
    SendEv e(dummyMsg, false, false, TEST_EVENT_ID);
    ASSERT_TRUE(b.addToSendQueue(e));
    
    ASSERT_TRUE(b.packageAndSendSegments(TEST_SOCKET, segSize, segSize) == LocalCode::SUCCESS);
    ASSERT_EQ(interceptedPackets.size(), 1);
    ASSERT_EQ(interceptedPackets[0].getSegSize(), segSize);
      
}

TEST_F(SendAndPackageSegmentFixture, SendPiggybackFin){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    uint32_t segSize = 50;
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    std::deque<uint8_t> dummyMsg(segSize);
    SendEv e(dummyMsg, false, false, TEST_EVENT_ID);
    ASSERT_TRUE(b.addToSendQueue(e));
    CloseEv ce(TEST_EVENT_ID);
    b.registerClose(ce);
    
    ASSERT_TRUE(b.packageAndSendSegments(TEST_SOCKET, segSize + 1, segSize) == LocalCode::SUCCESS);
    ASSERT_TRUE(interceptedPackets.size() == 1);
    ASSERT_EQ(interceptedPackets[0].getSegSize(), segSize + 1);
    ASSERT_TRUE(interceptedPackets[0].getFlag(TcpPacketFlags::FIN));
      
}

TEST_F(SendAndPackageSegmentFixture, ConcatTwoSends){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    uint32_t segSize = 50;
    uint32_t segSizeSecond = 100;
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    std::deque<uint8_t> dummyMsg(segSize);
    std::deque<uint8_t> dummyMsgSecond(segSizeSecond);
    SendEv e(dummyMsg, false, false, TEST_EVENT_ID);
    SendEv eSecond(dummyMsgSecond, false, false, TEST_EVENT_ID);
    ASSERT_TRUE(b.addToSendQueue(e));
    ASSERT_TRUE(b.addToSendQueue(eSecond));
    
    ASSERT_TRUE(b.packageAndSendSegments(TEST_SOCKET, segSize + segSizeSecond, segSize + segSizeSecond) == LocalCode::SUCCESS);
    ASSERT_EQ(interceptedPackets.size(), 1);
    ASSERT_EQ(interceptedPackets[0].getSegSize(), segSize + segSizeSecond);
      
}

TEST_F(SendAndPackageSegmentFixture, UrgentSplitTwoSends){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    uint32_t segSize = 50;
    uint32_t segSizeSecond = 100;
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    std::deque<uint8_t> dummyMsg(segSize);
    std::deque<uint8_t> dummyMsgSecond(segSizeSecond);
    SendEv e(dummyMsg, false, false, TEST_EVENT_ID);
    SendEv eSecond(dummyMsgSecond, true, false, TEST_EVENT_ID);
    ASSERT_TRUE(b.addToSendQueue(e));
    ASSERT_TRUE(b.addToSendQueue(eSecond));
    
    ASSERT_TRUE(b.packageAndSendSegments(TEST_SOCKET, segSize + segSizeSecond, segSize + segSizeSecond) == LocalCode::SUCCESS);
    ASSERT_EQ(interceptedPackets.size(), 2);
    ASSERT_FALSE(interceptedPackets[0].getFlag(TcpPacketFlags::URG));
    ASSERT_EQ(interceptedPackets[0].getSegSize(), segSize);
    ASSERT_TRUE(interceptedPackets[1].getFlag(TcpPacketFlags::URG));
    ASSERT_EQ(interceptedPackets[1].getUrg(), segSizeSecond - 1);
    ASSERT_EQ(interceptedPackets[1].getSegSize(), segSizeSecond);
      
}

TEST_F(SendAndPackageSegmentFixture, UrgentConcatTwoSendsWithPush){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    uint32_t segSize = 50;
    uint32_t segSizeSecond = 100;
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    std::deque<uint8_t> dummyMsg(segSize);
    std::deque<uint8_t> dummyMsgSecond(segSizeSecond);
    SendEv e(dummyMsg, true, false, TEST_EVENT_ID);
    SendEv eSecond(dummyMsgSecond, false, true, TEST_EVENT_ID);
    ASSERT_TRUE(b.addToSendQueue(e));
    ASSERT_TRUE(b.addToSendQueue(eSecond));
    
    ASSERT_TRUE(b.packageAndSendSegments(TEST_SOCKET, segSize + segSizeSecond, segSize + segSizeSecond) == LocalCode::SUCCESS);
    ASSERT_EQ(interceptedPackets.size(), 1);
    ASSERT_EQ(interceptedPackets[0].getSegSize(), segSize + segSizeSecond);
    ASSERT_TRUE(interceptedPackets[0].getFlag(TcpPacketFlags::URG));
    ASSERT_EQ(interceptedPackets[0].getUrg(), segSize - 1);
    ASSERT_TRUE(interceptedPackets[0].getFlag(TcpPacketFlags::PSH));
      
}

TEST_F(SendAndPackageSegmentFixture, HalfSendsWithPush){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    uint32_t segSize = 50;
    uint32_t msgSize = segSize * 2;
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    std::deque<uint8_t> dummyMsg(msgSize);
    
    SendEv e(dummyMsg, false, true, TEST_EVENT_ID);
    ASSERT_TRUE(b.addToSendQueue(e));
    
    ASSERT_TRUE(b.packageAndSendSegments(TEST_SOCKET, segSize, segSize) == LocalCode::SUCCESS);
    ASSERT_EQ(interceptedPackets.size(), 1);
    ASSERT_EQ(interceptedPackets[0].getSegSize(), segSize);  
    ASSERT_FALSE(interceptedPackets[1].getFlag(TcpPacketFlags::PSH));
    ASSERT_FALSE(b.noSendsOutstanding());
    ASSERT_TRUE(b.packageAndSendSegments(TEST_SOCKET, segSize, segSize) == LocalCode::SUCCESS);
    ASSERT_EQ(interceptedPackets.size(), 2);
    ASSERT_EQ(interceptedPackets[1].getSegSize(), segSize); 
    ASSERT_TRUE(interceptedPackets[1].getFlag(TcpPacketFlags::PSH));
    ASSERT_TRUE(b.noSendsOutstanding());
    
}



}

