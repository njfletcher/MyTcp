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

	Option o(OptionKind::noOp,0,0);	
	o.print();
	
	Option o1(OptionKind::end,0,0);	
	o1.print();

	Packet p;
	p.setFlags(0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0);
	p.setPorts(0x1000,0x1000);
	p.setNumbers(0x12345678, 0x87654321);
	p.setDataOffRes(0x06, 0x00);
	p.setWindowCheckUrg(0x1234, 0x4321, 0x1243);
	vector<Option> v = {o,o,o,o1};
	p.setOptions(v);
	vector<uint8_t> v1 = {0x1, 0x2, 0x33};
	p.setPayload(v1);
	p.print();
	
	sendPacket(dest, p);
	
	return 0;
}
