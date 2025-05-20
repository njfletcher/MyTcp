#include "packet.h"
#include <iostream>

using namespace std;


Option::Option(OptionKind k, uint8_t len, uint8_t hasLen): kind(k), length(len), hasLength(hasLen){};

void Option::print(){

	cout << "==OPTION==" << endl;
	cout << "kind: " << static_cast<unsigned int>(kind) << endl;
	cout << "length: " << static_cast<unsigned int>(length) << endl;
	cout << "hasLength: " << static_cast<unsigned int>(hasLength) << endl;
	cout << "data: [";
	for(int i = 0; i < data.size(); i++) cout << " " << static_cast<unsigned int>(data[i]);
	cout << "]" << endl;
	cout << "==========" << endl;


}

vector<uint8_t> Option::toBuffer(){

	vector<uint8_t> ret;
	ret.push_back(static_cast<uint8_t>(kind));
	if(hasLength){
		ret.push_back(length);
	}
	
	for(size_t i = 0; i < data.size(); i++){
		ret.push_back(data[i]);
	}
	
	return ret;
}


void Packet::setFlags(uint8_t cwr, uint8_t ece, uint8_t urg, uint8_t ack, uint8_t psh, uint8_t rst, uint8_t syn, uint8_t fin){

	uint8_t byte = 0;
	byte = byte | ((cwr & 0x1) << static_cast<int>(PacketFlags::cwr));
	byte = byte | ((ece & 0x1) << static_cast<int>(PacketFlags::ece));
	byte = byte | ((urg & 0x1) << static_cast<int>(PacketFlags::urg));
	byte = byte | ((ack & 0x1) << static_cast<int>(PacketFlags::ack));
	byte = byte | ((psh & 0x1) << static_cast<int>(PacketFlags::psh));
	byte = byte | ((rst & 0x1) << static_cast<int>(PacketFlags::rst));
	byte = byte | ((syn & 0x1) << static_cast<int>(PacketFlags::syn));
	byte = byte | ((fin & 0x1) << static_cast<int>(PacketFlags::fin));

	flags = byte;
}

PacketFlags& operator++(PacketFlags& p, int i){
	
	switch(p){	
		case PacketFlags::cwr:
			p = PacketFlags::ece;
			break;
		case PacketFlags::ece:
			p = PacketFlags::urg;
			break;
		case PacketFlags::urg:
			p = PacketFlags::ack;
			break;
		case PacketFlags::ack:
			p = PacketFlags::psh;
			break;
		case PacketFlags::psh:
			p = PacketFlags::rst;
			break;
		case PacketFlags::rst:
			p = PacketFlags::syn;
			break;
		case PacketFlags::syn:
			p = PacketFlags::fin;
			break;
		case PacketFlags::fin:
			p = PacketFlags::none;
			break;
		case PacketFlags::none:
			p = PacketFlags::none;
			break;	
	
	}
	return p;

}

uint8_t Packet::getFlag(PacketFlags flag){

	if (flag == PacketFlags::none) return 0;
	
	return (flags >> static_cast<int>(flag)) & 0x1;
}


uint8_t Packet::getDataOffset(){

	return (dataOffReserved & 0xf0) >> 4;
}
uint8_t Packet::getReserved(){

        return (dataOffReserved & 0xf);
}

uint16_t Packet::getDestPort(){

	return destPort;
}

uint16_t Packet::getSrcPort(){
	
	return sourcePort;
}

void Packet::print(){

	cout << "--------Packet--------" << endl;
	cout << "sourcePort: " << sourcePort << endl;
	cout << "destPort: " << destPort  << endl;
	cout << "seqNum: " << seqNum  << endl;
	cout << "ackNum: " << ackNum  << endl;
	cout << "dataOffset: " << static_cast<unsigned int>(getDataOffset()) << endl;
	cout << "reserved: " << static_cast<unsigned int>(getReserved())  << endl;
	cout << "+++Flags+++" << endl;
	for(PacketFlags p = PacketFlags::cwr; p != PacketFlags::none; p++) cout << "flag " << static_cast<unsigned int>(p) << ": " << static_cast<unsigned int>(getFlag(p)) << endl;
	cout << "+++++++++++" << endl;
	cout << "window: " << window << endl;
	cout << "checksum: " << checksum  << endl;
	cout << "urgPointer: " << urgPointer << endl;
	cout << "optionList: " << endl;
	for(size_t i = 0; i < optionList.size(); i++) optionList[i].print();
	cout << "payload: [" << endl;
	for(size_t i = 0; i < payload.size(); i++) cout << static_cast<unsigned int>(payload[i]) << " ";
	cout << " ]" << endl;
	cout << "----------------------" << endl;

}

void Packet::setPorts(uint16_t source, uint16_t dest){
	sourcePort = source;
	destPort = dest;

}
void Packet::setNumbers(uint32_t seq, uint32_t ack){
	seqNum = seq;
	ackNum = ack;
}
void Packet::setDataOffRes(uint8_t dataOff, uint8_t res){
	dataOffReserved = (res & 0xf) | ((dataOff & 0xf) << 4);

}
void Packet::setWindowCheckUrg(uint16_t win, uint16_t check, uint16_t urg){
	window = win;
	checksum = check;
	urgPointer = urg;
}
void Packet::setOptions(vector<Option> list){
	optionList = list;
}
void Packet::setPayload(vector<uint8_t> data){
	payload = data;

}


vector<uint8_t> Packet::toBuffer(){

	vector<uint8_t> ret;
	ret.push_back(((sourcePort & 0xFF00) >> 8) & 0xFF);
	ret.push_back(sourcePort & 0x00FF);
	
	ret.push_back(((destPort & 0xFF00) >> 8) & 0xFF);
	ret.push_back(destPort & 0x00FF);

	ret.push_back(((seqNum & 0xFF000000) >> 24) & 0xFF);
	ret.push_back(((seqNum & 0x00FF0000) >> 16) & 0xFF);
	ret.push_back(((seqNum & 0x0000FF00) >> 8) & 0xFF);
	ret.push_back(seqNum & 0x000000FF);

	ret.push_back(((ackNum & 0xFF000000) >> 24) & 0xFF);
	ret.push_back(((ackNum & 0x00FF0000) >> 16) & 0xFF);
	ret.push_back(((ackNum & 0x0000FF00) >> 8) & 0xFF);
	ret.push_back(ackNum & 0x000000FF);
	
	ret.push_back(dataOffReserved);
	ret.push_back(flags);
	
	ret.push_back(((window & 0xFF00) >> 8) & 0xFF);
	ret.push_back(window & 0x00FF);
	
	ret.push_back(((checksum & 0xFF00) >> 8) & 0xFF);
	ret.push_back(checksum & 0x00FF);
	
	ret.push_back(((urgPointer & 0xFF00) >> 8) & 0xFF);
	ret.push_back(urgPointer & 0x00FF);
	
	for(size_t i = 0; i < optionList.size(); i++){
	
		vector<uint8_t> opt = optionList[i].toBuffer();
		for(size_t j = 0; j < opt.size(); j++){
		
			ret.push_back(opt[j]);
		}
	
	}
	
	for(size_t i = 0; i < payload.size(); i++){
		ret.push_back(payload[i]);
	
	}
	
	return ret;

}


