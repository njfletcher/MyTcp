
#define TEST_NO_SEND 1
#include "../src/state.h"
#include <iostream>

#define testAppId 0
#define testSocket 0

const unsigned int testLocIp = 1;
const unsigned int testLocPort = 1;
const unsigned int testRemIp = 1;
const unsigned int testRemPort = 1;

using namespace std;

int testsPassed = 0;
int totalTests = 0;

void clear(){
  connections.clear();
  idMap.clear();
}

#define assert(call) \
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
    
    if(lc != LocalCode::Success){
      cout << "Bad return value " << static_cast<unsigned int>(lc) << endl;
      return false;
    }
    
    ConnPair cPair(lp,rp);
    
    if(connections.find(cPair) == connections.end()){
      cout << "Connection not made" << endl;
      return false;
    }
    
    if(idMap.size() < 1){
      cout << "Id not made" << endl;
      return false;
    }
    
    Tcb& b = connections[cPair];
    State& testS = *b.currentState;
    
    if(passive){
      if(!b.passiveOpen){
        cout << "Passive open but no indication" << endl;
        return false;
      }  
      if(!dynamic_cast<ListenS*>(&testS)){
        cout << "Should be in listen state" << endl;
        return false;
      }
    }
    else{
      if((b.sUna != b.iss) || (b.sNxt != (b.iss + 1))){
        cout << "Starting state wrong for active open" << endl;
        return false;
      }
      if(!dynamic_cast<SynSentS*>(&testS)){
        cout << "Should be in syn sent state" << endl;
        return false;
      }
    
    }
    
    
    return true;
}

bool testOpenRemUnspec(bool passive){

    cout << "Testing open remote unspec with passive "<< passive << endl;
    LocalPair lp(testLocIp,testLocPort);
    RemotePair rp(Unspecified, Unspecified);
    int createdId = 0;
    LocalCode lc = open(testAppId, testSocket, passive, lp, rp, createdId);
    
    if(lc != LocalCode::Success){
      cout << "Bad return value " << static_cast<unsigned int>(lc) << endl;
      return false;
    }
    
    ConnPair cPair(lp,rp);
    
    if(!passive){
      if(connections.find(cPair) != connections.end() || idMap.size() > 0){
        cout << "Connection should not have been made in open with unspec remote" << endl;
        return false;
      }
    }
    else{
      if(connections.find(cPair) == connections.end() || idMap.size() < 1){
        cout << "Connection should have been made in open with unspec remote" << endl;
        return false;
      }
    }
  
    return true;
}

bool testOpenLocUnspec(){

    cout << "Testing open with local unspec" <<  endl;

    LocalPair lp(Unspecified,Unspecified);
    RemotePair rp(testRemIp, testRemPort);
    int createdId = 0;
    LocalCode lc = open(testAppId, testSocket, true, lp, rp, createdId);
    
    if(lc != LocalCode::Success){
      cout << "Bad return value " << static_cast<unsigned int>(lc) << endl;
      return false;
    }
      
    if(connections.size() < 1){
      cout << "Connection not made" << endl;
      return false;
    }
    
    if(idMap.size() < 1){
      cout << "Id not made" << endl;
      return false;
    }
    
    Tcb& b = connections.begin()->second;
    if(b.lP.first == Unspecified || b.lP.second == Unspecified){
      cout << "local unspecified not filled in" << endl;
      return false;
    }
    
    return true;

}


int main(int argc, char** argv){

  assert(testOpenComplete(true))
  assert(testOpenComplete(false))
  assert(testOpenRemUnspec(true))
  assert(testOpenRemUnspec(false))
  assert(testOpenLocUnspec())
  

  cout << testsPassed << " tests passed out of " << totalTests << endl;
  return 0;
  
}
