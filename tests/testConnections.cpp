
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

bool testOpenComplete(bool passive){

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
    if(passive){
      if(!b.passiveOpen){
        cout << "Passive open but no indication" << endl;
        return false;
      }  
    }
    else{
      if((b.sUna != b.iss) || (b.sNxt != (b.iss + 1))){
        cout << "Starting state wrong for active open" << endl;
        return false;
      }
    
    }
    
    
    return true;
}


int main(int argc, char** argv){

  int totalTests = 0;
  int testsPassed = 0;
  totalTests++;
  if(testOpenComplete(true)){
      testsPassed++;
  }
  else{
      cout << "passive open complete FAILED" << endl;
  }
  
  totalTests++;
  if(testOpenComplete(false)){
      testsPassed++;
  }
  else{
      cout << "active open complete FAILED" << endl;
  }
  
  cout << testsPassed << " tests passed out of " << totalTests << endl;
  return 0;
  
}
