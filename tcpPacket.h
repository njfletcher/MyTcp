#pragma once
#include <vector>
#include <cstdint>
#include <queue>

#define tcpMinHeaderLen 20
#define defaultTcpDataOffset 5


enum class TcpOptionKind{
  end = 0,
  noOp = 1,
  mss = 2
};

class TcpOption{
  public:
    TcpOption() = default;
    TcpOption(uint8_t k, uint8_t len, bool hasLen, std::vector<uint8_t> data);
    bool fromBuffer(uint8_t* bufferPtr, int numBytesRemaining, int& retBytes);
    void print();
    void toBuffer(std::vector<uint8_t>& buff);
    uint16_t getSize();
    uint16_t calcSize();
    
    uint16_t size;
    uint8_t kind;
    uint8_t length;
    bool hasLength; 
    std::vector<uint8_t> data;

};

enum class TcpPacketFlags{
	
  fin = 0,
  syn = 1,
  rst = 2,
  psh = 3,
  ack = 4,
  urg = 5,
  ece = 6,
  cwr = 7
};



class TcpSegmentSlice{
  public:
    bool push;
    uint32_t seqNum;
    std::queue<uint8_t> unreadData;
};

class TcpPacket{

  public:
    TcpPacket();
    TcpPacket& setFlag(TcpPacketFlags flag);
    TcpPacket& setSrcPort(uint16_t source);
    TcpPacket& setDestPort(uint16_t dest);
    TcpPacket& setSeq(uint32_t seq);
    TcpPacket& setAck(uint32_t ack);
    TcpPacket& setDataOffset(uint8_t dataOffset);
    TcpPacket& setReserved(uint8_t reserved);
    TcpPacket& setWindow(uint16_t window);
    TcpPacket& setChecksum(uint16_t check);
    TcpPacket& setRealChecksum(uint32_t sourceAddress, uint32_t destAddress);
    TcpPacket& setUrgentPointer(uint16_t urg);
    TcpPacket& setOptions(std::vector<TcpOption> list);
    TcpPacket& setPayload(std::vector<uint8_t> payload);
    
    bool fromBuffer(uint8_t* buffer, int numBytes);
    void toBuffer(std::vector<uint8_t>& buff);
    void print();

    uint16_t getDestPort();
    uint16_t getSrcPort();
    uint32_t getSeqNum();
    uint32_t getAckNum();
    uint16_t getWindow();
    uint16_t getUrg();
    uint32_t getSegSize();
    uint16_t calcSize();
    bool getFlag(TcpPacketFlags flag);
    uint8_t getDataOffset();
    uint8_t getReserved();
    
    std::vector<uint8_t> payload;
    std::vector<TcpOption> optionList;
    
    //all multi-byte fields are guaranteed to be in host byte order.
  private:
    uint16_t size = 0;
    uint16_t sourcePort = 0;
    uint16_t destPort = 0;
    uint32_t seqNum = 0;
    uint32_t ackNum = 0;
    uint8_t dataOffReserved = 0;
    uint8_t flags = 0;
    uint16_t window = 0;
    uint16_t checksum = 0;
    uint16_t urgPointer = 0;
};

