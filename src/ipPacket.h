#pragma once
#include <vector>
#include <cstdint>
#include "tcpPacket.h"

const int IP_MIN_HEADER_LEN = 20;
const int IP_PACKET_MAX_SIZE = 65535;
const int NUM_IP_PACKET_FLAGS = 3;

enum class IpPacketCode{
  SUCCESS = 0,
  OPTIONS = -1,
  HEADER = -2,
  PAYLOAD = -3
};

enum class IpOptionType{

  EOOL = 0,
  NOOP = 1,
  SEC = 2,
  RR = 7,
  ZSU = 10,
  MTUP = 11,
  MTUR = 12,
  ENCODE = 15,
  QS = 25,
  EXP = 30,
  TS = 68,
  TR = 82,
  EXP2 = 94,
  SEC2 = 130,
  LSR = 131,
  ESEC = 133,
  CIPSO = 134,
  SID = 136,
  SSR = 137,
  VISA = 142,
  IMITD = 144,
  EIP = 145,
  ADDEXT = 147,
  RTRALT = 148,
  SDB = 149,
  DPS = 151,
  UMP = 152,
  EXP3 = 158,
  FINN = 205,
  EXP4 = 222
};

class IpOption{
  public:
    IpOption() = default;
    IpOption(uint8_t t, uint8_t len, bool hasLen);
    void print();
    void toBuffer(std::vector<uint8_t>& buff);
    bool fromBuffer(uint8_t* bufferPtr, int numBytesRemaining, int& retBytes);
    
    uint8_t getType();
    uint8_t getLength();
    bool getHasLength();
    std::vector<uint8_t>& getData();
  private:
    uint8_t type;
    uint8_t length;
    bool hasLength; 
    std::vector<uint8_t> data;
};

enum class IpPacketFlags{
  MOREFRAG = 0,
  DONTFRAG = 1,
  RESERVED = 2
};

class IpPacket{

  public:
    IpPacket() = default;
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
    
    uint32_t getSrcAddr();
    uint32_t getDestAddr();
    uint8_t getVersion();
    uint8_t getIHL();
    uint8_t getDscp();
    uint8_t getEcn();
    uint8_t getFlag(IpPacketFlags flag);
    uint16_t getFragOffset();
    uint16_t getTotalLength();
    uint16_t getIdent();
    uint8_t getTtl();
    uint8_t getProto();
    uint16_t getChecksum();
    
    uint32_t getOptionListByteCount();
    
    std::vector<IpOption>& getOptions();
    TcpPacket& getTcpPacket();
    
    IpPacketCode fromBuffer(uint8_t* buffer, int numBytes);
    void toBuffer(std::vector<uint8_t>& buff);
    void print();
    
  //all multi-byte fields are guaranteed to be in host byte order.
  private:
    uint8_t versionIHL = 0;
    uint8_t dscpEcn = 0;
    uint16_t totalLength = 0;
    uint16_t identification = 0;
    uint16_t flagsFragOffset = 0;
    uint8_t ttl = 0;
    uint8_t protocol = 0;
    uint16_t headerChecksum = 0;
    uint32_t sourceAddress = 0;
    uint32_t destAddress = 0;
    
    std::vector<IpOption> optionList;
    TcpPacket tcpPacket;
    
};







