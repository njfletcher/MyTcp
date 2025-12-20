#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/driver.h"
#include "testingUtil.h"
#include <iostream>

using namespace std;

namespace recAndReadSegmentTests{

TEST(RecReadSegmentTest, RecReadSimple){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
  
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<EstabS>());
    std::vector<uint8_t> dummyMsg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::vector<uint8_t> expected = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    TcpPacket p;
    p.setPayload(dummyMsg);
    b.processData(p);
    
    ReceiveEv e(dummyMsg.size(), {} , TEST_EVENT_ID);
    
    ASSERT_FALSE(b.processRead(e, false));
    vector<uint8_t>& userBuff = e.getBuffer();
    ASSERT_EQ(expected.size(), userBuff.size());
    for(int i =0; i < expected.size(); i++){
      EXPECT_EQ(expected[i], userBuff[i]);
    }
      
}

TEST(RecReadSegmentTest, TwoSegmentsNoOverlap){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
  
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<EstabS>());
    std::vector<uint8_t> dummyMsg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::vector<uint8_t> expected = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    TcpPacket p;
    p.setPayload(dummyMsg);
    b.processData(p);
    
    TcpPacket pNext;
    pNext.setPayload(dummyMsg);
    pNext.setSeq(dummyMsg.size());
    b.processData(pNext);
    
    ReceiveEv e(dummyMsg.size() * 2, {} , TEST_EVENT_ID);
    
    ASSERT_FALSE(b.processRead(e, false));
    vector<uint8_t>& userBuff = e.getBuffer();
    ASSERT_EQ(expected.size(), userBuff.size());
    for(int i =0; i < expected.size(); i++){
      EXPECT_EQ(expected[i], userBuff[i]);
    }
    
      
}

TEST(RecReadSegmentTest, TwoSegmentsOverlap){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
  
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<CloseWaitS>());
    std::vector<uint8_t> dummyMsg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::vector<uint8_t> expected = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 6, 7, 8, 9, 10};
    
    TcpPacket p;
    p.setPayload(dummyMsg);
    b.processData(p); 
    
    TcpPacket pNext;
    pNext.setPayload(dummyMsg);
    pNext.setSeq(dummyMsg.size() / 2);
    b.processData(pNext); 
    
    ReceiveEv e(dummyMsg.size() * 2, {} , TEST_EVENT_ID);
    
    ASSERT_FALSE(b.processRead(e, false));
    vector<uint8_t>& userBuff = e.getBuffer();
    ASSERT_EQ(expected.size(), userBuff.size());
    for(int i =0; i < expected.size(); i++){
      EXPECT_EQ(expected[i], userBuff[i]);
    }
    
}

TEST(RecReadSegmentTest, SegmentPushConsumed){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
  
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<CloseWaitS>());
    std::vector<uint8_t> dummyMsg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    TcpPacket p;
    p.setPayload(dummyMsg);
    p.setFlag(TcpPacketFlags::PSH);
    b.processData(p); 
        
    ReceiveEv e(dummyMsg.size(), {} , TEST_EVENT_ID);
    
    ASSERT_FALSE(b.processRead(e, false));  
    ASSERT_TRUE(b.getPushSeen());
    
}

TEST(RecReadSegmentTest, SegmentPushUnconsumed){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
  
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<CloseWaitS>());
    std::vector<uint8_t> dummyMsg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    TcpPacket p;
    p.setPayload(dummyMsg);
    p.setFlag(TcpPacketFlags::PSH);
    b.processData(p); 
        
    ReceiveEv e(dummyMsg.size() -1 , {} , TEST_EVENT_ID);
    
    ASSERT_TRUE(b.processRead(e, false));
    ASSERT_FALSE(b.getPushSeen());
    
}

TEST(RecReadSegmentTest, SegmentUrgentConsumed){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
  
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<CloseWaitS>());
    std::vector<uint8_t> dummyMsg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    TcpPacket p;
    p.setPayload(dummyMsg);
    p.setFlag(TcpPacketFlags::URG);
    p.setUrgentPointer(dummyMsg.size());

    b.processData(p);
    
    ReceiveEv e(dummyMsg.size(), {} , TEST_EVENT_ID);
    b.checkUrg(p,e);
    
    ASSERT_TRUE(b.getUrgentSignaled());
    ASSERT_FALSE(b.processRead(e, false));
    ASSERT_FALSE(b.getUrgentSignaled());
    
}

TEST(RecReadSegmentTest, SegmentUrgentUnconsumed){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
  
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<CloseWaitS>());
    std::vector<uint8_t> dummyMsg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    TcpPacket p;
    p.setPayload(dummyMsg);
    p.setFlag(TcpPacketFlags::URG);
    p.setUrgentPointer(dummyMsg.size());

    b.processData(p);
    
    ReceiveEv e(dummyMsg.size() - 1, {} , TEST_EVENT_ID);
    b.checkUrg(p,e);
    
    ASSERT_TRUE(b.getUrgentSignaled());
    ASSERT_TRUE(b.processRead(e, false));
    ASSERT_TRUE(b.getUrgentSignaled());
    
}


}

