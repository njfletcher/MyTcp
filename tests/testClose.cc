#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/driver.h"
#include "testingUtil.h"
#include <iostream>

using namespace std;


namespace closeTests{



class CloseTestFixture : public testing::Test{

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
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<T>());
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    LocalCode lc = close(&a, TEST_SOCKET, lp, rp);
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
      && (connNotifs[TEST_CONN_ID][0] == TcpCode::CONNCLOSING)
    );

}

template<typename before, typename after>
void testEmptySendQ(){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<before>());
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    LocalCode lc = close(&a, TEST_SOCKET, lp, rp);
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    
    Tcb& bNew = connections[cPair];
    
    State* testS = bNew.getCurrentState();
    ASSERT_TRUE(dynamic_cast<after*>(testS));
    
}

template<typename before, typename after>
void testNonEmptySendQ(){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<before>());
    SendEv e({},false,false,TEST_EVENT_ID);
    ASSERT_TRUE(b.addToSendQueue(e));
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    LocalCode lc = close(&a, TEST_SOCKET, lp, rp);
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    
    Tcb& bNew = connections[cPair];
    
    State* testS = bNew.getCurrentState();
    EXPECT_TRUE(dynamic_cast<after*>(testS));
    
    ASSERT_FALSE(bNew.noClosesOutstanding());

}

TEST_F(CloseTestFixture, CloseNoConn){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    App a(TEST_APP_ID, {}, {});
    LocalCode lc = close(&a, TEST_SOCKET, lp, rp);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
  
    EXPECT_TRUE(connections.size() < 1);
    EXPECT_TRUE(a.getAppNotifs().size() > 0);
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    EXPECT_EQ(a.getAppNotifs()[0] , TcpCode::NOCONNEXISTS);
    
}

TEST_F(CloseTestFixture, CloseListen){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<ListenS>());
    ReceiveEv e(1, {}, TEST_EVENT_ID);
    
    ASSERT_TRUE(b.addToRecQueue(e));
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    LocalCode lc = close(&a, TEST_SOCKET, lp, rp);
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(connections.size() < 1);
  
    std::unordered_map<int, std::deque<TcpCode> >& connNotifs = a.getConnNotifs();
    ASSERT_TRUE(
      (connNotifs.find(TEST_CONN_ID) != connNotifs.end()) 
      && (connNotifs[TEST_CONN_ID].size() == 1) 
      && (connNotifs[TEST_CONN_ID].front() == TcpCode::CLOSING)
    );
        
}

TEST_F(CloseTestFixture, CloseSynSent){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<SynSentS>());
    ReceiveEv e(1, {}, TEST_EVENT_ID);
    SendEv sE({},false,false,TEST_EVENT_ID);
    ASSERT_TRUE(b.addToRecQueue(e));
    ASSERT_TRUE(b.addToSendQueue(sE));
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    LocalCode lc = close(&a, TEST_SOCKET, lp, rp);
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(connections.size() < 1);
  
    std::unordered_map<int, std::deque<TcpCode> >& connNotifs = a.getConnNotifs();
    ASSERT_TRUE(
      (connNotifs.find(TEST_CONN_ID) != connNotifs.end()) 
      && (connNotifs[TEST_CONN_ID].size() == 2) 
      && (connNotifs[TEST_CONN_ID][0] == TcpCode::CLOSING)
      && (connNotifs[TEST_CONN_ID][1] == TcpCode::CLOSING)
      
    );
        
}

TEST_F(CloseTestFixture, CloseSynRecEmptySendQ){
  testEmptySendQ<SynRecS, FinWait1S>();            
}

TEST_F(CloseTestFixture, CloseSynRecNonEmptySendQ){
  testNonEmptySendQ<SynRecS, SynRecS>();            
}

TEST_F(CloseTestFixture, CloseEstabEmptySendQ){
  testEmptySendQ<EstabS,FinWait1S>();            
}

TEST_F(CloseTestFixture, CloseEstabNonEmptySendQ){
  testNonEmptySendQ<EstabS, FinWait1S>();            
}

TEST_F(CloseTestFixture, CloseFinWait1){
  testSimpleNotif<FinWait1S>();
}

TEST_F(CloseTestFixture, CloseFinWait2){
  testSimpleNotif<FinWait2S>();      
}

TEST_F(CloseTestFixture, CloseCloseWaitEmptySendQ){
  testEmptySendQ<CloseWaitS, LastAckS>();            
}

TEST_F(CloseTestFixture, CloseCloseWaitNonEmptySendQ){
  testNonEmptySendQ<CloseWaitS, LastAckS>();            
}

TEST_F(CloseTestFixture, CloseClosing){
  testSimpleNotif<ClosingS>();
}

TEST_F(CloseTestFixture, CloseLastAck){
  testSimpleNotif<LastAckS>();
}

TEST_F(CloseTestFixture, CloseTimeWait){
  testSimpleNotif<TimeWaitS>();
}

}
