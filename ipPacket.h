#pragma once
#include <vector>
#include <cstdint>
#include "tcpPacket.h"

#define ipMinHeaderLen 20
#define ipPacketMaxSize 65535
#define numIpPacketFlags 3

enum class IpPacketCode{
  Success = 0,
  Options = -1,
  Header = -2,
  Payload = -3
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
    IpOption(uint8_t t, uint8_t len, bool hasLen);
    void print();
    void toBuffer(std::vector<uint8_t>& buff);
    bool fromBuffer(uint8_t* bufferPtr, int numBytesRemaining, int& retBytes);
    uint8_t type;
    uint8_t length;
    bool hasLength; 
    std::vector<uint8_t> data;
};

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
    
    uint32_t getSrcAddr();
    uint32_t getDestAddr();
    uint8_t getVersion();
    uint8_t getIHL();
    uint8_t getDscp();
    uint8_t getEcn();
    uint8_t getFlag(IpPacketFlags flag);
    uint16_t getFragOffset();
    
    uint32_t getOptionListByteCount();
    
    IpPacketCode fromBuffer(uint8_t* buffer, int numBytes);
    void toBuffer(std::vector<uint8_t>& buff);
    void print();

    std::vector<IpOption> optionList;
    TcpPacket tcpPacket;
    
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
    
};







