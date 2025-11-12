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

class CloseTestFixture : public testing::Test{

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
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<T*>(&testS));
    
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId][0] == TcpCode::ConnClosing)
    );

}

template<typename before, typename after>
void testEmptySendQ(){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<before>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    Tcb& bNew = connections[cPair];
    
    State& testS = *bNew.currentState;
    ASSERT_TRUE(dynamic_cast<after*>(&testS));
    
}

template<typename before, typename after>
void testNonEmptySendQ(){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<before>();
    SendEv e;
    b.sendQueue.push_back(e);
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    Tcb& bNew = connections[cPair];
    
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<after*>(&testS));
    
    ASSERT_TRUE(bNew.closeQueue.size() > 0);

}

TEST_F(CloseTestFixture, CloseNoConn){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    App a;
    LocalCode lc = close(&a, testSocket, lp, rp);
    
    ASSERT_EQ(lc , LocalCode::Success);
  
    EXPECT_TRUE(connections.size() < 1);
    EXPECT_TRUE(a.appNotifs.size() > 0);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    EXPECT_EQ(a.appNotifs[0] , TcpCode::NoConnExists);
    
}

TEST_F(CloseTestFixture, CloseListen){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<ListenS>();
    ReceiveEv e;
    b.recQueue.push_back(e);
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(connections.size() < 1);
  
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId].front() == TcpCode::Closing)
    );
        
}

TEST_F(CloseTestFixture, CloseSynSent){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<SynSentS>();
    ReceiveEv e;
    SendEv sE;
    b.recQueue.push_back(e);
    b.sendQueue.push_back(sE);
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(connections.size() < 1);
  
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 2) 
      && (a.connNotifs[testConnId][0] == TcpCode::Closing)
      && (a.connNotifs[testConnId][1] == TcpCode::Closing)
      
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


