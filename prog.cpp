#include "packet.h"
#include "network.h"
#include <iostream>

using namespace std;
int main(int argc, char* argv[]){

	if(argc < 2){
		cout << "Need a destination ip." << endl;
		return -1;
		
	}
	
	char* dest = argv[2];

	OptionKind k = OptionKind::noOp;
	Option o(k,1);
	
	o.print();

	Packet p;
	p.setFlags(0x1, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0x0);
	p.setPorts(0x1234,0x4321);
	p.setNumbers(0x12345678, 0x87654321);
	p.setDataOffRes(0x01, 0x02);
	p.setWindowCheckUrg(0x1234, 0x4321, 0x1243);
	vector<Option> v = {o};
	p.setOptions(v);
	vector<uint8_t> v1 = {0x1, 0x2, 0x33};
	p.setPayload(v1);
	p.print();
	
	sendPacket(dest, p);
	
	return 0;
}
