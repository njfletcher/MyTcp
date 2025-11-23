#include "ipPacket.h"
#include "tcpPacket.h"
#include "network.h"
#include <iostream>
using namespace std;

IpOption::IpOption(uint8_t t, uint8_t len, bool hasLen): type(t), length(len), hasLength(hasLen){};

uint8_t IpOption::getType(){ return type; }
uint8_t IpOption::getLength(){ return length; }
bool IpOption::getHasLength(){ return hasLength; }
vector<uint8_t>& IpOption::getData() { return data; }

void IpOption::print(){

  cout << "==IpOption==" << endl;
  cout << "type: " << static_cast<unsigned int>(type) << endl;
  cout << "length: " << static_cast<unsigned int>(length) << endl;
  cout << "hasLength: " << static_cast<unsigned int>(hasLength) << endl;
  cout << "data: [";
  for(int i = 0; i < data.size(); i++) cout << " " << static_cast<unsigned int>(data[i]);
  cout << "]" << endl;
  cout << "==========" << endl;
  
}

void IpOption::toBuffer(vector<uint8_t>& buff){
  buff.push_back(type);
  if(hasLength){
	  buff.push_back(length);
  }

  for(size_t i = 0; i < data.size(); i++){
	  buff.push_back(data[i]);
  }
  
}

//numBytesRemaining val is assumed to be greater than 0.
bool IpOption::fromBuffer(uint8_t* buffer, int numBytesRemaining, int& retBytes){
  
  int numBytesRead = 0;
  uint8_t t = buffer[0];
  numBytesRead = numBytesRead + 1;
  
  type = t;
  if( t == static_cast<uint8_t>(IpOptionType::EOOL)){
      hasLength = false;
      retBytes = numBytesRemaining; //even if ihl claims there are more bytes, eool means that reading needs to stop.
      return true;
  }

  if(t == static_cast<uint8_t>(IpOptionType::NOOP) || numBytesRemaining < 2){
      hasLength = false;
      retBytes = numBytesRead;
      return true;
  }
  
  uint8_t len = buffer[1];
  numBytesRead = numBytesRead + 1;
  length = len;
  hasLength = true;
  
  uint8_t dataLength = length -2; // to account for length and type field
  
  if(dataLength > (numBytesRemaining-2)) return false;
  
  for(uint8_t i = 0; i < dataLength; i++){
    data.push_back(buffer[2 + i]);
  }
  numBytesRead = numBytesRead + dataLength;
  retBytes = numBytesRead;
  return true;
}

IpPacket& IpPacket::setVersion(uint8_t vers){
  versionIHL = (versionIHL & 0x0F) | ((vers & 0xf) << 4);
  return *this;
}

IpPacket& IpPacket::setIHL(uint8_t ihl){
  versionIHL = (versionIHL & 0xF0) | (ihl & 0xf);
  return *this;
}

IpPacket& IpPacket::setDSCP(uint8_t dscp){
  dscpEcn = (dscpEcn & 0x03) | ((dscp & 0x3f) << 2);
  return *this;
}

IpPacket& IpPacket::setEcn(uint8_t ecn){
  dscpEcn = (dscpEcn & 0xFC) | (ecn & 0x3);
  return *this;
}

IpPacket& IpPacket::setTotLen(uint16_t len){
  totalLength = len;
  return *this;
}

IpPacket& IpPacket::setIdent(uint16_t ident){
  identification = ident;
  return *this;
}

IpPacket& IpPacket::setFragOff(uint16_t frag){
  flagsFragOffset = (flagsFragOffset & 0xE000) | (frag & 0x01FFF);
  return *this;
}

IpPacket& IpPacket::setTtl(uint8_t ttl){
  this->ttl = ttl;
  return *this;
}

IpPacket& IpPacket::setProto(uint8_t proto){
  protocol = proto;
  return *this;
}

IpPacket& IpPacket::setHeadCheck(uint16_t check){
  headerChecksum = check;
  return *this;
}

IpPacket& IpPacket::setSrcAddr(uint32_t addr){
  sourceAddress = addr;
  return *this;
}

IpPacket& IpPacket::setDestAddr(uint32_t addr){
  destAddress = addr;
  return *this;
}


uint32_t IpPacket::getSrcAddr(){ return sourceAddress;}
uint32_t IpPacket::getDestAddr(){ return destAddress;}

uint8_t IpPacket::getVersion(){
  return (versionIHL & 0xF0) >> 4;
}
uint8_t IpPacket::getIHL(){
  return (versionIHL & 0x0F);
}
uint8_t IpPacket::getDscp(){
  return (dscpEcn & 0xFC) >> 2;
}
uint8_t IpPacket::getEcn(){
  return (dscpEcn & 0x3);
}
uint8_t IpPacket::getFlag(IpPacketFlags flag){
  uint8_t flags = ((flagsFragOffset & 0xE000) >> (16 - NUM_IP_PACKET_FLAGS)) & 0xFF;
  return (flags >> static_cast<int>(flag)) & 0x1;
}

IpPacket& IpPacket::setFlag(IpPacketFlags flag){
  uint8_t flags = ((flagsFragOffset & 0xE000) >> (16 - NUM_IP_PACKET_FLAGS)) & 0xFF;
  flags = flags | (0x1 << static_cast<int>(flag));
  flagsFragOffset = (flagsFragOffset & 0x01FFF) | (flags << (16 - NUM_IP_PACKET_FLAGS));
  return *this;
}

uint16_t IpPacket::getFragOffset(){
  return (flagsFragOffset & 0x01FFF);
}

uint16_t IpPacket::getTotalLength(){ return totalLength;}
uint16_t IpPacket::getIdent(){ return identification;}
uint8_t IpPacket::getTtl(){ return ttl;}
uint8_t IpPacket::getProto(){return protocol;}
uint16_t IpPacket::getChecksum(){return headerChecksum;}
std::vector<IpOption>& IpPacket::getOptions(){ return optionList; }
TcpPacket& IpPacket::getTcpPacket(){ return tcpPacket; }


void IpPacket::print(){

	cout << "++++++++IpPacket++++++++" << endl;
	cout << "version: " << static_cast<unsigned int>(getVersion()) << endl;
	cout << "ihl: " << static_cast<unsigned int>(getIHL())  << endl;
	cout << "dscp: " << static_cast<unsigned int>(getDscp())   << endl;
	cout << "ecn: " <<  static_cast<unsigned int>(getEcn()) << endl;
	cout << "total length: " << totalLength << endl;
	cout << "identification: " << identification  << endl;
	cout << "///Flags///" << endl;
	for(int i = static_cast<int>(IpPacketFlags::MOREFRAG); i < static_cast<int>(IpPacketFlags::RESERVED) + 1; i++) cout << "flag " << i << ": " << static_cast<unsigned int>(getFlag(static_cast<IpPacketFlags>(i))) << endl;
	cout << "///////////" << endl;
	cout << "fragment offset: " << getFragOffset() << endl;
	cout << "ttl: " << static_cast<unsigned int>(ttl)  << endl;
	cout << "protocol: " << static_cast<unsigned int>(protocol) << endl;
	cout << "header checksum: " << headerChecksum << endl;
	cout << "source address: " << sourceAddress << endl;
	cout << "dest address: " << destAddress << endl;
	cout << "IpOptionList: " << endl;
	for(size_t i = 0; i < optionList.size(); i++) optionList[i].print();
	tcpPacket.print();
	cout << "++++++++++++++++++++++++" << endl;

}

void IpPacket::toBuffer(vector<uint8_t>& buff){

	buff.push_back(versionIHL);
	buff.push_back(dscpEcn);
	
	loadBytes<uint16_t>(toAltOrder<uint16_t>(totalLength), buff); 
	loadBytes<uint16_t>(toAltOrder<uint16_t>(identification), buff);
	loadBytes<uint16_t>(toAltOrder<uint16_t>(flagsFragOffset), buff);
	
	buff.push_back(ttl);
	buff.push_back(protocol);
	
	loadBytes<uint16_t>(toAltOrder<uint16_t>(headerChecksum), buff);
	loadBytes<uint32_t>(toAltOrder<uint32_t>(sourceAddress), buff);
        loadBytes<uint32_t>(toAltOrder<uint32_t>(destAddress), buff);
		
	for(size_t i = 0; i < optionList.size(); i++) optionList[i].toBuffer(buff);	
        tcpPacket.toBuffer(buff);
}

uint32_t IpPacket::getOptionListByteCount(){
  uint32_t num = 0;
  for(auto i = optionList.begin(); i < optionList.end(); i++){
    IpOption o = *i;
    num = num + 1; //kind byte
    if(o.getHasLength()){
      num = num + 1;
    }
    num = num + o.getData().size();
    
  }
  return num;
}


/*
IpPacket fromBuffer
takes raw bytes and fills in the ip packet with them.
*/
IpPacketCode IpPacket::fromBuffer(uint8_t* buffer, int numBytes){
  
  if(numBytes < IP_MIN_HEADER_LEN){
    return IpPacketCode::HEADER;
  }
  
  versionIHL = buffer[0];
  dscpEcn = buffer[1];
  totalLength = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,2));
  identification = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,4));
  flagsFragOffset = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,6));
  ttl = buffer[8];
  protocol = buffer[9];
  headerChecksum = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,10));
  sourceAddress = toAltOrder<uint32_t>(unloadBytes<uint32_t>(buffer,12));
  destAddress = toAltOrder<uint32_t>(unloadBytes<uint32_t>(buffer,16));
  
  uint8_t ihlConv = getIHL() * 4;
  if(ihlConv < IP_MIN_HEADER_LEN || ihlConv > numBytes) return IpPacketCode::HEADER;
  
  uint8_t* currPointer = buffer + IP_MIN_HEADER_LEN;
  
  vector<IpOption> options;
  
  if(ihlConv > IP_MIN_HEADER_LEN){
    
    int optionBytesRemaining = ihlConv - IP_MIN_HEADER_LEN;
    while(optionBytesRemaining > 0){
        IpOption o;
        int numBytesRead = 0;
        bool rs = o.fromBuffer(currPointer, optionBytesRemaining, numBytesRead);
        if(!rs) return IpPacketCode::HEADER;
        currPointer = currPointer + numBytesRead;
        optionBytesRemaining = optionBytesRemaining - numBytesRead;
        options.push_back(o);
    }
    optionList = options;
  }
  
  int bytesRemaining = numBytes - ihlConv;
  TcpPacketCode c = tcpPacket.fromBuffer(currPointer, bytesRemaining);
  if(c != TcpPacketCode::SUCCESS)return IpPacketCode::PAYLOAD;
  else return IpPacketCode::SUCCESS;
}

