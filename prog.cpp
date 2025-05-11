#include "packet.h"


int main(int argc, char* argv[]){

	OptionKind k = OptionKind::noOp;
	Option o(k,1);
	
	o.print();

	return 0;
}
