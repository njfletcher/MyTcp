
#include "test.h"
#define TEST_NO_SEND 1
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

int testsPassed = 0;
int totalTests = 0;

void clear(){
  connections.clear();
  idMap.clear();
}

bool testOpenComplete(bool passive){

    cout << "Testing open complete with passive " << passive << endl;

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    int createdId = 0;
    App a;
    LocalCode lc = open(&a, testSocket, passive, lp, rp, createdId);
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
  
    ConnPair cPair(lp,rp);
    
    assert(connections.find(cPair) != connections.end(), "Connection not made")
    assert(idMap.size() > 0, "Id not made")
    
    assert(a.appNotifs.size() < 1, "App should have no notifs")
    assert(a.connNotifs.size() < 1, "Conns should have no notifs")
    
    Tcb& b = connections[cPair];
    
    State& testS = *b.currentState;
    
    if(passive){
      assert(b.passiveOpen, "Passive open but no indication")
      assert(dynamic_cast<ListenS*>(&testS), "Should be in listen state")
    }
    else{
      assert((b.sUna == b.iss) && (b.sNxt == (b.iss + 1)), "Starting state wrong for active open")
      assert(dynamic_cast<SynSentS*>(&testS), "Should be in syn sent state")
    }
    
    clear();
    return true;
}

bool testOpenRemUnspec(bool passive){

    cout << "Testing open remote unspec with passive "<< passive << endl;
    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(Unspecified, Unspecified);
    int createdId = 0;
    App a;
    LocalCode lc = open(&a, testSocket, passive, lp, rp, createdId);
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
    
    ConnPair cPair(lp,rp);
    
    assert(a.connNotifs.size() < 1, "Connections should have no notifs")
    
    if(!passive){
      assert((a.appNotifs.size() > 0) && (a.appNotifs.front() == TcpCode::ActiveUnspec), "Should have been notified of active unspec")
      assert(connections.find(cPair) == connections.end() && idMap.size() < 1, "Connection should not have been made in open with unspec remote")
    }
    else{
      assert(connections.find(cPair) != connections.end() && idMap.size() > 0, "Connection should have been made in open with unspec remote")
    }
    clear();
    return true;
}

bool testOpenLocUnspec(){

    cout << "Testing open with local unspec" <<  endl;

    LocalPair lp(Unspecified,Unspecified);
    RemotePair rp(testRemIp, testRemPort);
    int createdId = 0;
    App a;
    LocalCode lc = open(&a, testSocket, true, lp, rp, createdId);
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
      
    assert(connections.size() > 0, "Connection not made")
    assert(idMap.size() > 0, "Id not made")
    
    assert(a.appNotifs.size() < 1, "App should have no notifs")
    assert(a.connNotifs.size() < 1, "Conns should have no notifs")
    
    Tcb& b = connections.begin()->second;
    assert(b.lP.first != Unspecified && b.lP.second != Unspecified, "local unspecified not filled in ")
    
    clear();
    return true;

}

bool testListenOpen(bool passive){

    cout << "Testing open complete starting from listen state with passive " << passive << endl;

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    App a;
    Tcb b(&a, lp, rp, true);
    b.id = testConnId;
    b.currentState = make_shared<ListenS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    int createdId = 0;
    
    LocalCode lc = open(&a, testSocket, passive, lp, rp, createdId);
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
    
    Tcb& bAfter = connections[cPair];
    State& testS = *bAfter.currentState;
    
    if(passive){
      assert(bAfter.passiveOpen, "Should have passive open indication after second passive open")
      assert(dynamic_cast<ListenS*>(&testS), "Should be in listen state still")
      assert(a.appNotifs.size() < 1, "App should have no notifs")
      assert((a.connNotifs.find(testConnId) != a.connNotifs.end()) && (a.connNotifs[testConnId].size() > 0) && (a.connNotifs[testConnId].front() == TcpCode::DupConn) , "Conn should have dupp conn notif")
    }
    else{
      assert((bAfter.sUna == bAfter.iss) && (bAfter.sNxt == (bAfter.iss + 1)), "Starting state wrong for active open")
      assert(dynamic_cast<SynSentS*>(&testS), "Should be in syn sent state")
      assert(!bAfter.passiveOpen, "Should have no passive indication after switch to active")
    }
    
    clear();
    return true;
}

bool testListenOpenActiveRemUnspec(){

    cout << "Testing open starting from listen state with active and rem unspec" << endl;

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
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
    
    Tcb& bAfter = connections[cPair];
    State& testS = *bAfter.currentState;

    assert(bAfter.passiveOpen, "Should stay as passive open")
    assert(dynamic_cast<ListenS*>(&testS), "Should still be in listen state")
    assert((a.appNotifs.size() > 0) && (a.appNotifs.front() == TcpCode::ActiveUnspec) , "Conn should have active unspec notif")
    
    clear();
    return true;
}

int main(int argc, char** argv){

  test(testOpenComplete(true))
  test(testOpenComplete(false))
  test(testOpenRemUnspec(true))
  test(testOpenRemUnspec(false))
  test(testOpenLocUnspec())
  test(testListenOpen(true))
  test(testListenOpen(false))
  test(testListenOpenActiveRemUnspec())
  
  cout << testsPassed << " tests passed out of " << totalTests << endl;
  return 0;
}
