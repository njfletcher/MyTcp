#include <gtest/gtest.h>
#include "../src/state.h"
#include "../src/driver.h"
#include "testingUtil.h"
#include <iostream>

using namespace std;

namespace openTests{



class OpenTestFixture : public testing::Test{

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
    
    int createdId = 0;
    LocalCode lc = open(&a, TEST_SOCKET, false, lp, rp, createdId);
  
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
      && (connNotifs[TEST_CONN_ID][0] == TcpCode::DUPCONN)
    );

}

TEST_F(OpenTestFixture, OpenCompleteActive){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    int createdId = 0;
    App a(TEST_APP_ID, {}, {});
    LocalCode lc = open(&a, TEST_SOCKET, false, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
  
    ConnPair cPair(lp,rp);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    EXPECT_TRUE(idMap.size() > 0);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    
    Tcb& b = connections[cPair];
    
    State* testS = b.getCurrentState();
  
    ASSERT_TRUE(dynamic_cast<SynSentS*>(testS));
    
}

TEST_F(OpenTestFixture, OpenCompletePassive){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    int createdId = 0;
    App a(TEST_APP_ID, {}, {});
    LocalCode lc = open(&a, TEST_SOCKET, true, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
  
    ConnPair cPair(lp,rp);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    EXPECT_TRUE(idMap.size() > 0);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    
    Tcb& b = connections[cPair];
    
    State* testS = b.getCurrentState();
    
    
    EXPECT_TRUE(b.wasPassiveOpen());
    ASSERT_TRUE(dynamic_cast<ListenS*>(testS));
}



TEST_F(OpenTestFixture, OpenRemUnspecPassive){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(UNSPECIFIED, UNSPECIFIED);
    int createdId = 0;
    App a(TEST_APP_ID, {}, {});
    LocalCode lc = open(&a, TEST_SOCKET, true, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    ConnPair cPair(lp,rp);
    
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    ASSERT_TRUE(connections.find(cPair) != connections.end() && idMap.size() > 0);
}

TEST_F(OpenTestFixture, OpenRemUnspecActive){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(UNSPECIFIED, UNSPECIFIED);
    int createdId = 0;
    App a(TEST_APP_ID, {}, {});
    LocalCode lc = open(&a, TEST_SOCKET, false, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    ConnPair cPair(lp,rp);
    
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    
    EXPECT_TRUE((a.getAppNotifs().size() > 0) && (a.getAppNotifs().front() == TcpCode::ACTIVEUNSPEC));
    ASSERT_TRUE(connections.find(cPair) == connections.end() && idMap.size() < 1);
    
}

TEST_F(OpenTestFixture, OpenLocUnspec){

    LocalPair lp(UNSPECIFIED,UNSPECIFIED);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    int createdId = 0;
    App a(TEST_APP_ID, {}, {});
    LocalCode lc = open(&a, TEST_SOCKET, true, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
      
    ASSERT_TRUE(connections.size() > 0);
    EXPECT_TRUE(idMap.size() > 0);
    
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    EXPECT_TRUE(a.getConnNotifs().size() < 1);
    
    Tcb& b = connections.begin()->second;
    ConnPair cPair = b.getConnPair();
    ASSERT_TRUE(cPair.first.first != UNSPECIFIED && cPair.first.second != UNSPECIFIED);
    
}

TEST_F(OpenTestFixture, OpenFromListenPassive){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<ListenS>());
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    int createdId = 0;
    LocalCode lc = open(&a, TEST_SOCKET, true, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    Tcb& bAfter = connections[cPair];
    State* testS = bAfter.getCurrentState();
    
    EXPECT_TRUE(bAfter.wasPassiveOpen());
    EXPECT_TRUE(dynamic_cast<ListenS*>(testS));
    EXPECT_TRUE(a.getAppNotifs().size() < 1);
    std::unordered_map<int, std::deque<TcpCode> >& connNotifs = a.getConnNotifs();
    ASSERT_TRUE(
      (connNotifs.find(TEST_CONN_ID) != connNotifs.end()) 
      && (connNotifs[TEST_CONN_ID].size() > 0) 
      && (connNotifs[TEST_CONN_ID].front() == TcpCode::DUPCONN)
    );
    
}

TEST_F(OpenTestFixture, OpenFromListenActive){

    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(TEST_REM_IP, TEST_REM_PORT);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    
    b.setCurrentState(make_unique<ListenS>());
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b);
    
    int createdId = 0;
    LocalCode lc = open(&a, TEST_SOCKET, false, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    Tcb& bAfter = connections[cPair];
    State* testS = bAfter.getCurrentState();
        
    EXPECT_TRUE(dynamic_cast<SynSentS*>(testS));
    ASSERT_FALSE(bAfter.wasPassiveOpen());
}

TEST_F(OpenTestFixture, OpenListenActiveRemUnspec){
    
    LocalPair lp(TEST_LOC_IP,TEST_LOC_PORT);
    RemotePair rp(UNSPECIFIED, UNSPECIFIED);
    
    App a(TEST_APP_ID, {}, {});
    Tcb b(&a, lp, rp, true, TEST_CONN_ID);
    b.setCurrentState(make_unique<ListenS>());
  
    ConnPair cPair(lp,rp);
    connections[cPair] = move(b); 
    
    int createdId = 0;
    LocalCode lc = open(&a, TEST_SOCKET, false, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::SUCCESS);
    
    Tcb& bAfter = connections[cPair];
    State* testS = bAfter.getCurrentState();

    EXPECT_TRUE(bAfter.wasPassiveOpen());
    EXPECT_TRUE(dynamic_cast<ListenS*>(testS));
    ASSERT_TRUE((a.getAppNotifs().size() > 0) && (a.getAppNotifs().front() == TcpCode::ACTIVEUNSPEC));
    
}

TEST_F(OpenTestFixture, OpenExistingSynSent){
  testSimpleNotif<SynSentS>();
}
TEST_F(OpenTestFixture, OpenExistingSynRec){
  testSimpleNotif<SynRecS>();
}
TEST_F(OpenTestFixture, OpenExistingEstab){
  testSimpleNotif<EstabS>();
}
TEST_F(OpenTestFixture, OpenExistingFinWait1){
  testSimpleNotif<FinWait1S>();
}
TEST_F(OpenTestFixture, OpenExistingFinWait2){
  testSimpleNotif<FinWait2S>();
}
TEST_F(OpenTestFixture, OpenExistingCloseWait){
  testSimpleNotif<CloseWaitS>();
}
TEST_F(OpenTestFixture, OpenExistingClosing){
  testSimpleNotif<ClosingS>();
}
TEST_F(OpenTestFixture, OpenExistingLastAck){
  testSimpleNotif<LastAckS>();
}
TEST_F(OpenTestFixture, OpenExistingTimeWait){
  testSimpleNotif<TimeWaitS>();
}

}

