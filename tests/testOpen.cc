#include <gtest/gtest.h>
#include "../src/state.h"
#include <iostream>

using namespace std;

#define testAppId 0
#define testSocket 0
#define testConnId 1

const unsigned int testLocIp = 1;
const unsigned int testLocPort = 1;
const unsigned int testRemIp = 1;
const unsigned int testRemPort = 1;

class OpenTestFixture : public testing::Test{

  void TearDown() override{
    connections.clear();
    idMap.clear();
  }
};

template<typename T>
void testSimpleNotif(){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<T>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    int createdId = 0;
    LocalCode lc = open(&a, testSocket, false, lp, rp, createdId);
  
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<T*>(&testS));
    
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId][0] == TcpCode::DupConn)
    );

}

TEST_F(OpenTestFixture, OpenCompleteActive){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    int createdId = 0;
    App a;
    LocalCode lc = open(&a, testSocket, false, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::Success);
  
    ConnPair cPair(lp,rp);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    EXPECT_TRUE(idMap.size() > 0);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    Tcb& b = connections[cPair];
    
    State& testS = *b.currentState;
    
    EXPECT_TRUE((b.sUna == b.iss) && (b.sNxt == (b.iss + 1)));
    ASSERT_TRUE(dynamic_cast<SynSentS*>(&testS));
    
}

TEST_F(OpenTestFixture, OpenCompletePassive){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    int createdId = 0;
    App a;
    LocalCode lc = open(&a, testSocket, true, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::Success);
  
    ConnPair cPair(lp,rp);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    EXPECT_TRUE(idMap.size() > 0);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    Tcb& b = connections[cPair];
    
    State& testS = *b.currentState;
    
    
    EXPECT_TRUE(b.passiveOpen);
    ASSERT_TRUE(dynamic_cast<ListenS*>(&testS));
}



TEST_F(OpenTestFixture, OpenRemUnspecPassive){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(Unspecified, Unspecified);
    int createdId = 0;
    App a;
    LocalCode lc = open(&a, testSocket, true, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::Success);
    
    ConnPair cPair(lp,rp);
    
    EXPECT_TRUE(a.connNotifs.size() < 1);
    ASSERT_TRUE(connections.find(cPair) != connections.end() && idMap.size() > 0);
}

TEST_F(OpenTestFixture, OpenRemUnspecActive){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(Unspecified, Unspecified);
    int createdId = 0;
    App a;
    LocalCode lc = open(&a, testSocket, false, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::Success);
    
    ConnPair cPair(lp,rp);
    
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    EXPECT_TRUE((a.appNotifs.size() > 0) && (a.appNotifs.front() == TcpCode::ActiveUnspec));
    ASSERT_TRUE(connections.find(cPair) == connections.end() && idMap.size() < 1);
    
}

TEST_F(OpenTestFixture, OpenLocUnspec){

    LocalPair lp(Unspecified,Unspecified);
    RemotePair rp(testRemIp, testRemPort);
    int createdId = 0;
    App a;
    LocalCode lc = open(&a, testSocket, true, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::Success);
      
    ASSERT_TRUE(connections.size() > 0);
    EXPECT_TRUE(idMap.size() > 0);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    Tcb& b = connections.begin()->second;
    ASSERT_TRUE(b.lP.first != Unspecified && b.lP.second != Unspecified);
    
}

TEST_F(OpenTestFixture, OpenFromListenPassive){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<ListenS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    int createdId = 0;
    LocalCode lc = open(&a, testSocket, true, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::Success);
    
    Tcb& bAfter = connections[cPair];
    State& testS = *bAfter.currentState;
    
    EXPECT_TRUE(bAfter.passiveOpen);
    EXPECT_TRUE(dynamic_cast<ListenS*>(&testS));
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() > 0) 
      && (a.connNotifs[testConnId].front() == TcpCode::DupConn)
    );
    
}

TEST_F(OpenTestFixture, OpenFromListenActive){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<ListenS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    int createdId = 0;
    LocalCode lc = open(&a, testSocket, false, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::Success);
    
    Tcb& bAfter = connections[cPair];
    State& testS = *bAfter.currentState;
        
    
    EXPECT_TRUE((bAfter.sUna == bAfter.iss) && (bAfter.sNxt == (bAfter.iss + 1)));
    EXPECT_TRUE(dynamic_cast<SynSentS*>(&testS));
    ASSERT_FALSE(bAfter.passiveOpen);
}

TEST_F(OpenTestFixture, OpenListenActiveRemUnspec){
    
    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(Unspecified, Unspecified);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.currentState = make_shared<ListenS>();
    b.id = testConnId;
    ConnPair cPair(lp,rp);
    connections[cPair] = b; 
    
    int createdId = 0;
    LocalCode lc = open(&a, testSocket, false, lp, rp, createdId);
    
    ASSERT_EQ(lc , LocalCode::Success);
    
    Tcb& bAfter = connections[cPair];
    State& testS = *bAfter.currentState;

    EXPECT_TRUE(bAfter.passiveOpen);
    EXPECT_TRUE(dynamic_cast<ListenS*>(&testS));
    ASSERT_TRUE((a.appNotifs.size() > 0) && (a.appNotifs.front() == TcpCode::ActiveUnspec));
    
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


















