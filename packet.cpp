#include "packet.h"
#include <iostream>

using namespace std;


Option::Option(OptionKind k, uint8_t len): kind(k), length(len){};

void Option::print(){

	cout << "==OPTION==" << endl;
	cout << "kind: " << static_cast<int>(kind) << endl;
	cout << "length: " << static_cast<int>(length) << endl;
	cout << "data: ";
	for(int i = 0; i < data.size(); i++){
	
		cout << " " << data[i];
	
	}
	cout << endl;
	cout << "==========" << endl;


}
