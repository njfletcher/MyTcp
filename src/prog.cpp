#include "ipPacket.h"
#include "tcpPacket.h"
#include "network.h"
#include <iostream>
#include "state.h"
#include "driver.h"

using namespace std;

int main(int argc, char* argv[]){

	if(argc < 2){
		cout << "Need a destination ip." << endl;
		return -1;
		
	}
	
	cout << argv[1] << endl;
        
        LocalPair lp(0,0);
        RemotePair rp(0, 0);
  
        App a(0, {}, {});
        Tcb b(&a, lp, rp, true, 0);
        b.setCurrentState(make_unique<EstabS>());
        std::vector<uint8_t> dummyMsg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
        TcpPacket p;
        p.setPayload(dummyMsg);
        b.processData(p);
    
         TcpPacket pNext;
    pNext.setPayload(dummyMsg);
    pNext.setSeq(dummyMsg.size() / 2);
    b.processData(pNext); 
    
    ReceiveEv e(dummyMsg.size() * 2, {} , 0);
    
        b.processRead(e, false);
        

	return 0;
}
