#include "packet.h"
#include "network.h"
#include <iostream>

using namespace std;
int main(int argc, char* argv[]){

	if(argc < 2){
		cout << "Need a destination ip." << endl;
		return -1;
		
	}
	
	char* dest = argv[1];

	TcpOption o(0x1,0,0);	
	o.print();
	
	TcpOption o1(0x0,0,0);	
	o1.print();

	TcpPacket p;
	vector<TcpOption> v = {o,o,o,o1};
	vector<uint8_t> v1 = {0x1, 0x2, 0x33};
	
	p.setFlags(0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0).setSrcPort(0x1000).setDestPort(0x1000).setSeq(0x12345678).setAck(0x87654321).setDataOffset(0x06).setReserved(0x00).setWindow(0x1234).setChecksum(0x4321).setUrgentPointer(0x1243).setOptions(v).setPayload(v1);
        
        //p.print();
        
	IpPacket packet;
	int ret = sendPacket(dest, p, packet);
	
        packet.print();
      
	return 0;
}
