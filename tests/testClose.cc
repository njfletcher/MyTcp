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

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<SynRecS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    Tcb& bNew = connections[cPair];
    
    State& testS = *bNew.currentState;
    ASSERT_TRUE(dynamic_cast<FinWait1S*>(&testS));
            
}

TEST_F(CloseTestFixture, CloseSynRecNonEmptySendQ){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<SynRecS>();
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
    EXPECT_TRUE(dynamic_cast<SynRecS*>(&testS));
    
    ASSERT_TRUE(bNew.closeQueue.size() > 0);
            
}

TEST_F(CloseTestFixture, CloseEstabEmptySendQ){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<EstabS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    Tcb& bNew = connections[cPair];
    
    State& testS = *bNew.currentState;
    ASSERT_TRUE(dynamic_cast<FinWait1S*>(&testS));
            
}

TEST_F(CloseTestFixture, CloseEstabNonEmptySendQ){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<EstabS>();
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
    EXPECT_TRUE(dynamic_cast<FinWait1S*>(&testS));
    
    ASSERT_TRUE(bNew.closeQueue.size() > 0);
            
}

TEST_F(CloseTestFixture, CloseFinWait1){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<FinWait1S>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<FinWait1S*>(&testS));
    
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId][0] == TcpCode::ConnClosing)
    );
        
}

TEST_F(CloseTestFixture, CloseFinWait2){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<FinWait2S>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<FinWait2S*>(&testS));
    
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId][0] == TcpCode::ConnClosing)
    );
        
}

TEST_F(CloseTestFixture, CloseCloseWaitEmptySendQ){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<CloseWaitS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    ASSERT_NE(connections.find(cPair) , connections.end());
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    EXPECT_TRUE(a.connNotifs.size() < 1);
    
    Tcb& bNew = connections[cPair];
    
    State& testS = *bNew.currentState;
    ASSERT_TRUE(dynamic_cast<LastAckS*>(&testS));
            
}

TEST_F(CloseTestFixture, CloseCloseWaitNonEmptySendQ){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<CloseWaitS>();
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
    EXPECT_TRUE(dynamic_cast<LastAckS*>(&testS));
    
    ASSERT_TRUE(bNew.closeQueue.size() > 0);
            
}

TEST_F(CloseTestFixture, CloseClosing){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<ClosingS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<ClosingS*>(&testS));
    
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId][0] == TcpCode::ConnClosing)
    );
        
}

TEST_F(CloseTestFixture, CloseLastAck){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<LastAckS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<LastAckS*>(&testS));
    
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId][0] == TcpCode::ConnClosing)
    );
        
}

TEST_F(CloseTestFixture, CloseTimeWait){

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<TimeWaitS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    LocalCode lc = close(&a, testSocket, lp, rp);
    ASSERT_EQ(lc , LocalCode::Success);
    
    EXPECT_TRUE(a.appNotifs.size() < 1);
    ASSERT_NE(connections.find(cPair) , connections.end());
    Tcb& bNew = connections[cPair];
    State& testS = *bNew.currentState;
    EXPECT_TRUE(dynamic_cast<TimeWaitS*>(&testS));
    
    ASSERT_TRUE(
      (a.connNotifs.find(testConnId) != a.connNotifs.end()) 
      && (a.connNotifs[testConnId].size() == 1) 
      && (a.connNotifs[testConnId][0] == TcpCode::ConnClosing)
    );
        
}


