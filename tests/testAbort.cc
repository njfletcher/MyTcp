#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/driver.h"
#include "testingUtil.h"
#include <iostream>

using namespace std;

namespace abortTests{


class AbortTestFixture : public testing::Test{

  void TearDown() override{
    connections.clear();
    idMap.clear();
  }
};

template<typename T>
void testSimpleNotif(){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true,TEST_CONN_ID);
    b.setCurrentState(make_unique<T>());
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    LocalCode lc = abort(&a, TEST_SOCKET, lp, rp);
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State* testS = bNew.getCurrentState();
    EXPECT_TRUE(dynamic_cast<T*>(testS));
    
    std::unordered_map<int, std::deque<TcpCode> >& connNotifs = a.getConnNotifs();
    ASSERT_TRUE(
      (connNotifs.find(TEST_CONN_ID) != connNotifs.end()) 
      && (connNotifs[TEST_CONN_ID].size() == 1) 
      && (connNotifs[TEST_CONN_ID][0] == TcpCode::OK)
    );

}

template<typename T>
void testNormalAbort(){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<T>());
    ReceiveEv e(1,{},TEST_EVENT_ID);
    SendEv sE({},false,false,TEST_EVENT_ID);
    TcpPacket p;
    ASSERT_TRUE(b.addToSendQueue(sE));
    ASSERT_TRUE(b.addToRecQueue(e));
    ASSERT_TRUE(b.addToRetransmit(p));
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    Tcb& bNew = connections[cPair];
    
    LocalCode lc = abort(&a, TEST_SOCKET, lp, rp);
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(connections.size() < 1);
    EXPECT_TRUE(bNew.noRetransmitsOutstanding());
  
    std::unordered_map<int, std::deque<TcpCode> >& connNotifs = a.getConnNotifs();
    ASSERT_TRUE(
      (connNotifs.find(TEST_CONN_ID) != connNotifs.end()) 
      && (connNotifs[TEST_CONN_ID].size() == 2) 
      && (connNotifs[TEST_CONN_ID][0] == TcpCode::CONNRST)
      && (connNotifs[TEST_CONN_ID][1] == TcpCode::CONNRST)
      
    );
    

}

TEST_F(AbortTestFixture, AbortNoConn){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    App a(TEST_APP_ID, {}, {});
    LocalCode lc = abort(&a, TEST_SOCKET, lp, rp);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
  
    EXPECT_TRUE(connections.size() < 1);
    EXPECT_TRUE(a.getAppNotifs().size() > 0);
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    EXPECT_EQ(a.getAppNotifs()[0] , TcpCode::NOCONNEXISTS);
    
}

TEST_F(AbortTestFixture, AbortListen){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<ListenS>());
    ReceiveEv e(1,{},TEST_EVENT_ID);
    ASSERT_TRUE(b.addToRecQueue(e));
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    LocalCode lc = abort(&a, TEST_SOCKET, lp, rp);
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(connections.size() < 1);
  
    std::unordered_map<int, std::deque<TcpCode> >& connNotifs = a.getConnNotifs();
    ASSERT_TRUE(
      (connNotifs.find(TEST_CONN_ID) != connNotifs.end()) 
      && (connNotifs[TEST_CONN_ID].size() == 1) 
      && (connNotifs[TEST_CONN_ID].front() == TcpCode::CONNRST)
    );
        
}

TEST_F(AbortTestFixture, AbortSynSent){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true,TEST_CONN_ID);
    b.setCurrentState(make_unique<SynSentS>());
    ReceiveEv e(1,{},TEST_EVENT_ID);
    SendEv sE({},false,false,TEST_EVENT_ID);
    ASSERT_TRUE(b.addToRecQueue(e));
    ASSERT_TRUE(b.addToSendQueue(sE));
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    LocalCode lc = abort(&a, TEST_SOCKET, lp, rp);
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(connections.size() < 1);
  
    std::unordered_map<int, std::deque<TcpCode> >& connNotifs = a.getConnNotifs();
    ASSERT_TRUE(
      (connNotifs.find(TEST_CONN_ID) != connNotifs.end()) 
      && (connNotifs[TEST_CONN_ID].size() == 2) 
      && (connNotifs[TEST_CONN_ID][0] == TcpCode::CONNRST)
      && (connNotifs[TEST_CONN_ID][1] == TcpCode::CONNRST)
      
    );
        
}

TEST_F(AbortTestFixture, AbortSynRec){
  testNormalAbort<SynRecS>();            
}

TEST_F(AbortTestFixture, AbortEstab){
  testNormalAbort<EstabS>();            
}

TEST_F(AbortTestFixture, AbortFinWait1){
  testNormalAbort<FinWait1S>();            
}

TEST_F(AbortTestFixture, AbortFinWait2){
  testNormalAbort<FinWait2S>();            
}

TEST_F(AbortTestFixture, AbortCloseWait){
  testNormalAbort<CloseWaitS>();            
}

TEST_F(AbortTestFixture, AbortClosing){
  testSimpleNotif<ClosingS>();
}

TEST_F(AbortTestFixture, AbortLastAck){
  testSimpleNotif<LastAckS>();
}

TEST_F(AbortTestFixture, AbortTimeWait){
  testSimpleNotif<TimeWaitS>();
}

}
