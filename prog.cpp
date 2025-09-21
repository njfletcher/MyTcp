#include "ipPacket.h"
#include "tcpPacket.h"
#include "network.h"
#include <iostream>
#include "state.h"

using namespace std;

int main(int argc, char* argv[]){

	if(argc < 2){
		cout << "Need a destination ip." << endl;
		return -1;
		
	}
	
	cout << argv[1] << endl;
        Tcb b;
        
        int createdId = 0;
        LocalPair lp(0,0);
        RemotePair rp(0,0);
        Status s = open(0, false, lp, rp, createdId)

	return 0;
}
