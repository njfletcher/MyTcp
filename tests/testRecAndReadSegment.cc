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
    
    TcpPacket p;
    p.setPayload(dummyMsg);
    b.processData(p);
    
    ReceiveEv e(dummyMsg.size(), {} , TEST_EVENT_ID);
    
    ASSERT_TRUE(b.processRead(e, false));
    vector<uint8_t>& userBuff = e.getBuffer();
    ASSERT_EQ(dummyMsg.size(), userBuff.size());
    for(int i =0; i < dummyMsg.size(); i++){
      EXPECT_EQ(dummyMsg[i], userBuff[i]);
    }
      
}


}

