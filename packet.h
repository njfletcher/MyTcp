#pragma once
#include <vector>
#include <cstdint>

enum class OptionKind{

	end = 0,
	noOp = 1,
	maxSeqSize = 2,
	windScale = 3,
	selAckPerm = 4,
	selAck = 5,
	timestampEcho = 8,
	userTimeout = 28,
	tcpAuth = 29,
	multipath = 30

};

class Option{
	public:
		Option(OptionKind k, uint8_t len);
		void print();
	private:
		OptionKind kind;
		uint8_t length;
		std::vector<uint8_t> data;

};

class Packet{

	private:
		uint16_t sourcePort;
		uint16_t destPort;
	
		uint32_t seqNum;
		uint32_t ackNum;
		uint8_t dataOffAndReserved;
		uint8_t flags;
		uint16_t window;
	
		uint16_t checksum;
		uint16_t urgPointer;
		std::vector<Option> optionList;
		uint8_t* payload;

};
