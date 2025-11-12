#include <gtest/gtest.h>
#include "../src/state.h"
#include <iostream>

using namespace std;

namespace abortTests{
#define testAppId 0
#define testSocket 0
#define testConnId 1

const unsigned int testLocIp = 1;
const unsigned int testLocPort = 1;
const unsigned int testRemIp = 1;
const unsigned int testRemPort = 1;

class AbortTestFixture : public testing::Test{

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
    
    LocalCode lc = abort(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<T*>(&testS));
    
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId][0] == TcpCode::Ok)
    );

}

template<typename T>
void testNormalAbort(){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<T>();
    ReceiveEv e;
    SendEv sE;
    TcpPacket p;
    b.recQueue.push_back(e);
    b.sendQueue.push_back(sE);
    b.retransmit.push_back(p);
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    Tcb& bNew = connections[cPair];
    
    LocalCode lc = abort(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(connections.size() < 1);
    EXPECT_TRUE(bNew.retransmit.size() < 1);
  
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 2) 
      && (a.connNotifs[testConnId][0] == TcpCode::ConnRst)
      && (a.connNotifs[testConnId][1] == TcpCode::ConnRst)
      
    );
    

}

TEST_F(AbortTestFixture, AbortNoConn){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    App a;
    LocalCode lc = abort(&a, testSocket, lp, rp);
    
    ASSERT_EQ(lc , LocalCode::Success);
  
    EXPECT_TRUE(connections.size() < 1);
    EXPECT_TRUE(a.appNotifs.size() > 0);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    EXPECT_EQ(a.appNotifs[0] , TcpCode::NoConnExists);
    
}

TEST_F(AbortTestFixture, AbortListen){

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
    
    LocalCode lc = abort(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(connections.size() < 1);
  
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId].front() == TcpCode::ConnRst)
    );
        
}

TEST_F(AbortTestFixture, AbortSynSent){

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
    
    LocalCode lc = abort(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(connections.size() < 1);
  
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 2) 
      && (a.connNotifs[testConnId][0] == TcpCode::ConnRst)
      && (a.connNotifs[testConnId][1] == TcpCode::ConnRst)
      
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
