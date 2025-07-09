#pragma once
#include <vector>
#include <cstdint>

#define ipMinHeaderLen 20
#define tcpMinHeaderLen 20
#define ipPacketMaxSize 65535

enum class TcpOptionKind{

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

class TcpOption{
  public:
    TcpOption() = default;
    TcpOption(uint8_t k, uint8_t len, uint8_t hasLen, std::vector<uint8_t> data);
    int fromBuffer(uint8_t* bufferPtr, int numBytesRemaining);
    void print();
    void toBuffer(std::vector<uint8_t>& buff);
    uint16_t getSize();
  private:
    uint16_t calcSize();
    uint16_t size;
    uint8_t kind;
    uint8_t length;
    uint8_t hasLength; 
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

class TcpPacket{

  public:
    TcpPacket() = default;
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
    
    int fromBuffer(uint8_t* buffer, int numBytes);
    void toBuffer(std::vector<uint8_t>& buff);
    void print();

    uint16_t getDestPort();
    uint16_t getSrcPort();
    uint32_t getSeqNum();
    uint32_t getAckNum();
    uint16_t getWindow();
    
    uint32_t getSegSize();
    std::vector<uint8_t> payload;
    std::vector<TcpOption> optionList;
    
    //all multi-byte fields are guaranteed to be in host byte order.
  private:
    uint16_t calcSize();
    uint16_t size;
    
    uint8_t getFlag(TcpPacketFlags flag);
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

};


enum class IpOptionType{

  eool = 0,
  nop = 1,
  sec = 2,
  rr = 7,
  zsu = 10,
  mtup = 11,
  mtur = 12,
  encode = 15,
  qs = 25,
  exp = 30,
  ts = 68,
  tr = 82,
  exp2 = 94,
  sec2 = 130,
  lsr = 131,
  esec = 133,
  cipso = 134,
  sid = 136,
  ssr = 137,
  visa = 142,
  imitd = 144,
  eip = 145,
  addext = 147,
  rtralt = 148,
  sdb = 149,
  dps = 151,
  ump = 152,
  exp3 = 158,
  finn = 205,
  exp4 = 222
};

class IpOption{
  public:
    IpOption() = default;
    IpOption(uint8_t t, uint8_t len, uint8_t hasLen);
    void print();
    void toBuffer(std::vector<uint8_t>& buff);
    int fromBuffer(uint8_t* bufferPtr, int numBytesRemaining);
  private:
    uint8_t type;
    uint8_t length;
    uint8_t hasLength; 
    std::vector<uint8_t> data;
};

#define numIpPacketFlags 3
enum class IpPacketFlags{
  moreFrag = 0,
  dontFrag = 1,
  reserved = 2
};

class IpPacket{

  public:
    IpPacket();
    
    IpPacket& setVersion(uint8_t vers);
    IpPacket& setIHL(uint8_t ihl);
    IpPacket& setDSCP(uint8_t dscp);
    IpPacket& setEcn(uint8_t ecn);
    IpPacket& setTotLen(uint16_t len);
    IpPacket& setIdent(uint16_t ident);
    IpPacket& setFlag(IpPacketFlags f);
    IpPacket& setFragOff(uint16_t frag);
    IpPacket& setTtl(uint8_t ttl);
    IpPacket& setProto(uint8_t proto);
    IpPacket& setHeadCheck(uint16_t check);
    IpPacket& setSrcAddr(uint32_t addr);
    IpPacket& setDestAddr(uint32_t addr);
    IpPacket& setOptions(std::vector<IpOption> list);
    IpPacket& setTcpPacket(TcpPacket& packet);
    
    uint32_t getSrcAddr();
    uint32_t getDestAddr();
    
    int fromBuffer(uint8_t* buffer, int numBytes);
    void toBuffer(std::vector<uint8_t>& buff);
    void print();
    TcpPacket& getTcpPacket();
  //all multi-byte fields are guaranteed to be in host byte order.
  private:
    uint8_t getVersion();
    uint8_t getIHL();
    uint8_t getDscp();
    uint8_t getEcn();
    uint8_t getFlag(IpPacketFlags flag);
    uint16_t getFragOffset();
    
    uint8_t versionIHL;
    uint8_t dscpEcn;
    uint16_t totalLength;
    
    uint16_t identification;
    uint16_t flagsFragOffset;
    
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerChecksum;
    
    uint32_t sourceAddress;
    uint32_t destAddress;
    
    std::vector<IpOption> optionList;
    TcpPacket tcpPacket;
};
