
#define TEST_NO_SEND 1
#include "../src/state.h"
#include <iostream>

using namespace std;

#define testAppId 0
#define testSocket 0

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

#define assert(call, errorMsg) \
  if(!(call)){\
    cout << errorMsg << endl;\
    return false;\
  }\
  
#define test(call) \
  totalTests++; \
  if(call){\
      testsPassed++;\
      cout << "PASSED" << endl;\
  }\
  else{\
      cout << "FAILED" << endl;\
  }\
  clear();\


bool testOpenComplete(bool passive){

    cout << "Testing open complete with passive " << passive << endl;

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    int createdId = 0;
    LocalCode lc = open(testAppId, testSocket, passive, lp, rp, createdId);
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
  
    ConnPair cPair(lp,rp);
    
    assert(connections.find(cPair) != connections.end(), "Connection not made")
    assert(idMap.size() > 0, "Id not made")
    
    Tcb& b = connections[cPair];
    assert(b.notifQueue.empty(), "Connection should have no notifs")
    
    State& testS = *b.currentState;
    
    if(passive){
      assert(b.passiveOpen, "Passive open but no indication")
      assert(dynamic_cast<ListenS*>(&testS), "Should be in listen state")
    }
    else{
      assert((b.sUna == b.iss) && (b.sNxt == (b.iss + 1)), "Starting state wrong for active open")
      assert(dynamic_cast<SynSentS*>(&testS), "Should be in syn sent state")
    }
    
    
    return true;
}

bool testOpenRemUnspec(bool passive){

    cout << "Testing open remote unspec with passive "<< passive << endl;
    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(Unspecified, Unspecified);
    int createdId = 0;
    LocalCode lc = open(testAppId, testSocket, passive, lp, rp, createdId);
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
    
    ConnPair cPair(lp,rp);
    
    if(!passive){
      assert(connections.find(cPair) == connections.end() && idMap.size() < 1, "Connection should not have been made in open with unspec remote")
    }
    else{
      assert(connections.find(cPair) != connections.end() && idMap.size() > 0, "Connection should have been made in open with unspec remote"
    }
  
    return true;
}

bool testOpenLocUnspec(){

    cout << "Testing open with local unspec" <<  endl;

    LocalPair lp(Unspecified,Unspecified);
    RemotePair rp(testRemIp, testRemPort);
    int createdId = 0;
    LocalCode lc = open(testAppId, testSocket, true, lp, rp, createdId);
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
      
    assert(connections.size() > 0, "Connection not made")
    assert(idMap.size() > 0, "Id not made")
    
    Tcb& b = connections.begin()->second;
    assert(b.lP.first != Unspecified && b.lP.second != Unspecified, "local unspecified not filled in ")
    
    return true;

}

bool testListenOpen(bool passive){

    cout << "Testing open complete starting from listen state with passive " << passive << endl;

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(testRemIp, testRemPort);
    
    Tcb b(lp, rp, true);
    b.currentState = make_shared<ListenS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    int createdId = 0;
    LocalCode lc = open(testAppId, testSocket, passive, lp, rp, createdId);
    
    assert(lc == LocalCode::Success, "Bad return value " + to_string(static_cast<unsigned int>(lc)))
    
    Tcb& bAfter = connections[cPair];
    State& testS = *bAfter.currentState;
    
    if(passive){
      if(!bAfter.passiveOpen){
        cout << "Passive open but no indication" << endl;
        return false;
      }  
      if(!dynamic_cast<ListenS*>(&testS)){
        cout << "Should be in listen state" << endl;
        return false;
      }
    }
    else{
      if((bAfter.sUna != bAfter.iss) || (bAfter.sNxt != (bAfter.iss + 1))){
        cout << "Starting state wrong for active open" << endl;
        return false;
      }
      if(!dynamic_cast<SynSentS*>(&testS)){
        cout << "Should be in syn sent state" << endl;
        return false;
      }
      if(bAfter.passiveOpen){
        cout << "Should have been changed to active open" << endl;
        return false;
      }
    
    }
    
    
    return true;
}

bool testListenOpenActiveRemUnspec(){

    cout << "Testing open starting from listen state with active and rem unspec" << endl;

    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(Unspecified, Unspecified);
    
    Tcb b(lp, rp, true);
    b.currentState = make_shared<ListenS>();
    ConnPair cPair(lp,rp);
    connections[cPair] = b;
    
    int createdId = 0;
    LocalCode lc = open(testAppId, testSocket, false, lp, rp, createdId);
    
    if(lc != LocalCode::Success){
      cout << "Bad return value " << static_cast<unsigned int>(lc) << endl;
      return false;
    }
    
    Tcb& bAfter = connections[cPair];
    State& testS = *bAfter.currentState;
  
    if(!bAfter.passiveOpen){
      cout << "Passive open but no indication" << endl;
      return false;
    }  
    if(!dynamic_cast<ListenS*>(&testS)){
      cout << "Should be in listen state" << endl;
      return false;
    }
        
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
