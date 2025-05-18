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
		std::vector<uint8_t> toBuffer();
	private:
		OptionKind kind;
		uint8_t length;
		uint8_t hasLength; 
		std::vector<uint8_t> data;


};

enum class PacketFlags{

	cwr = 0, 
	ece = 1, 
	urg = 2,
	ack = 3, 
	psh = 4,
	rst = 5, 
	syn = 6, 
	fin = 7,
	none = 8
	
};

PacketFlags& operator++(PacketFlags& p, int);


class Packet{

	public:
		Packet() = default;
		void setFlags(uint8_t cwr, uint8_t ece, uint8_t urg, uint8_t ack, uint8_t psh, uint8_t rst, uint8_t syn, uint8_t fin);
		void setPorts(uint16_t source, uint16_t dest);
		void setNumbers(uint32_t seq, uint32_t ack);
		void setDataOffRes(uint8_t dataOffset, uint8_t reserved);
		void setWindowCheckUrg(uint16_t window, uint16_t check, uint16_t urg);
		void setOptions(std::vector<Option> list);
		void setPayload(std::vector<uint8_t> payload);
		std::vector<uint8_t> toBuffer();
		void print();
		
		uint16_t getDestPort();
		uint16_t getSrcPort();
	private:
		uint8_t getFlag(PacketFlags flag);
		uint8_t getDataOffset();
		uint8_t getReserved();
		
		uint16_t sourcePort;
		uint16_t destPort;
	
		uint32_t seqNum;
		uint32_t ackNum;
		uint8_t dataOffReserved;
		uint8_t flags;
		uint16_t window;
	
		uint16_t checksum;
		uint16_t urgPointer;
		std::vector<Option> optionList;
		std::vector<uint8_t> payload;

};
