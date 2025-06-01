#include "packet.h"
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
        IpPacket p = activeOpen(argv[1], b);
        p.print();
        
	return 0;
}
