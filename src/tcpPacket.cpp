#include "tcpPacket.h"
#include "network.h"
#include <iostream>

using namespace std;


bool TcpSegmentSlice::isPush(){ return push; }
uint32_t TcpSegmentSlice::getSeqNum(){ return seqNum; }
std::queue<uint8_t>& TcpSegmentSlice::getData() { return unreadData; }

TcpOption::TcpOption(uint8_t k, uint8_t len, bool hasLen, vector<uint8_t> d): kind(k), length(len), hasLength(hasLen), data(d){
  size = calcSize();
};

uint16_t TcpOption::calcSize(){
  uint16_t sz = 1; //kind
  if(hasLength){
    sz = sz + 1; //len byte
  }
  sz = sz + data.size();
  return sz;
}

uint16_t TcpOption::getSize(){
  return size;
}
uint8_t TcpOption::getKind(){
  return kind;
}
uint8_t TcpOption::getLength(){
  return length;
}
bool TcpOption::getHasLength(){
  return hasLength;
}
std::vector<uint8_t>& TcpOption::getData(){
  return data;
}

void TcpOption::print(){

  cout << "==TcpOption==" << endl;
  cout << "kind: " << static_cast<unsigned int>(kind) << endl;
  cout << "length: " << static_cast<unsigned int>(length) << endl;
  cout << "hasLength: " << static_cast<unsigned int>(hasLength) << endl;
  cout << "data: [";
  for(int i = 0; i < data.size(); i++) cout << " " << static_cast<unsigned int>(data[i]);
  cout << "]" << endl;
  cout << "==========" << endl;

}

void TcpOption::toBuffer(vector<uint8_t>& buff){
  buff.push_back(kind);
  if(hasLength){
	  buff.push_back(length);
  }

  for(size_t i = 0; i < data.size(); i++){
	  buff.push_back(data[i]);
  }
}

//numBytesRemaining val is assumed to be greater than 0.
bool TcpOption::fromBuffer(uint8_t* buffer, int numBytesRemaining, int& retBytes){
  
  int numBytesRead = 0;
  uint8_t k = buffer[0];
  numBytesRead = numBytesRead + 1;
  
  kind = k;
  if( k == static_cast<uint8_t>(TcpOptionKind::END)){
      hasLength = false;
      size = calcSize();
      retBytes = numBytesRemaining; //even if dataoffset claims there are more bytes, end means that reading needs to stop.
      return true;
  }
  if(k == static_cast<uint8_t>(TcpOptionKind::NOOP)){
      hasLength = false;
      size = calcSize();
      retBytes = numBytesRead;
      return true;
  }

  //at this point it is either the mss option or some other option. either way this option will have to have a length field according to RFC 9293 MUST68
  if(numBytesRemaining < 2) return false;
  
  uint8_t len = buffer[1];
  //length field includes itself and the kind byte. Anything less than 2 doesnt make sense
  if(len < 2) return false;
  if(k == static_cast<uint8_t>(TcpOptionKind::MSS) && len != 4) return false;
  
  numBytesRead = numBytesRead + 1;
  length = len;
  hasLength = true;
  
  uint8_t dataLength = len -2; // to account for length and type field
  
  if(dataLength > (numBytesRemaining-2)) return false;
  
  for(uint8_t i = 0; i < dataLength; i++){
    data.push_back(buffer[2 + i]);
  }
  numBytesRead = numBytesRead + dataLength;
  size = calcSize();
  retBytes = numBytesRead;
  return true;
  
}

void onesCompAdd(uint16_t& num1, uint16_t num2){

  uint32_t res = num1 + num2;
  if(res > 0xffff){
  
    res = (res & 0xffff) + 1;
  }
  num1 = static_cast<uint16_t>(res);
}

TcpPacket& TcpPacket::setRealChecksum(uint32_t sourceAddress, uint32_t destAddress){
  
  uint16_t accum = 0;
  onesCompAdd(accum, (sourceAddress & 0x0000FFFF));
  onesCompAdd(accum, (sourceAddress & 0xFFFF0000) >> 16);
  onesCompAdd(accum, (destAddress & 0x0000FFFF));
  onesCompAdd(accum, (destAddress & 0xFFFF0000) >> 16); 
  onesCompAdd(accum, 0x0006);
  
  onesCompAdd(accum,size);
  onesCompAdd(accum,sourcePort);
  onesCompAdd(accum,destPort);
  onesCompAdd(accum, seqNum & 0x0000FFFF);
  onesCompAdd(accum, (seqNum & 0xFFFF0000) >> 16);
  
  onesCompAdd(accum, ackNum & 0x0000FFFF);
  onesCompAdd(accum, (ackNum & 0xFFFF0000) >> 16);
  
  onesCompAdd(accum, (dataOffReserved << 8) | flags);
  onesCompAdd(accum, window);
  onesCompAdd(accum, 0x0000);// checksum is replaced by zeros
  onesCompAdd(accum, urgPointer);
  
  vector<uint8_t> optionsAndPayload;
  for(size_t i = 0; i < optionList.size(); i++){
    optionList[i].toBuffer(optionsAndPayload);
  }
  for(size_t i = 0; i < payload.size(); i++){
    optionsAndPayload.push_back(payload[i]);
  }
  if(optionsAndPayload.size() & 0x1){
    optionsAndPayload.push_back(0x00);
  }
  
  for(size_t i = 0; i < optionsAndPayload.size(); i+=2){
    uint8_t firstByte = optionsAndPayload[i];
    uint8_t secondByte = optionsAndPayload[i+1];
    uint16_t word = (firstByte << 8) | secondByte;
    onesCompAdd(accum,word);
  }
  
  checksum = ~accum;
  return *this;
}

bool TcpPacket::getFlag(TcpPacketFlags flag){
  return static_cast<bool>((flags >> static_cast<int>(flag)) & 0x1);
}

TcpPacket& TcpPacket::setFlag(TcpPacketFlags flag){
  flags = flags | (0x1 << static_cast<int>(flag));
  return *this;
}


uint16_t TcpPacket::calcSize(){
  uint16_t optSize = 0;
  for(auto iter = optionList.begin(); iter != optionList.end(); iter++){
    optSize += iter->calcSize();
  }
  
  return TCP_MIN_HEADER_LEN + optSize + payload.size(); 

}
uint8_t TcpPacket::getDataOffset(){

	return (dataOffReserved & 0xf0) >> 4;
}
uint8_t TcpPacket::getReserved(){

        return (dataOffReserved & 0xf);
}
uint16_t TcpPacket::getDestPort(){return destPort;}
uint16_t TcpPacket::getSrcPort(){return sourcePort;}
uint32_t TcpPacket::getSeqNum(){return seqNum;}
uint32_t TcpPacket::getAckNum(){return ackNum;}
uint16_t TcpPacket::getWindow(){return window;}
uint16_t TcpPacket::getUrg(){return urgPointer;}

void TcpPacket::print(){

	cout << "--------TcpPacket--------" << endl;
	cout << "sourcePort: " << sourcePort << endl;
	cout << "destPort: " << destPort  << endl;
	cout << "seqNum: " << seqNum  << endl;
	cout << "ackNum: " << ackNum  << endl;
	cout << "dataOffset: " << static_cast<unsigned int>(getDataOffset()) << endl;
	cout << "reserved: " << static_cast<unsigned int>(getReserved())  << endl;
	cout << "+++Flags+++" << endl;
	for(int i = static_cast<int>(TcpPacketFlags::FIN); i < static_cast<int>(TcpPacketFlags::CWR) + 1; i++) cout << "flag " << i << ": " << static_cast<unsigned int>(getFlag(static_cast<TcpPacketFlags>(i))) << endl;
	cout << "+++++++++++" << endl;
	cout << "window: " << window << endl;
	cout << "checksum: " << checksum  << endl;
	cout << "urgPointer: " << urgPointer << endl;
	cout << "TcpOptionList: " << endl;
	for(size_t i = 0; i < optionList.size(); i++) optionList[i].print();
	cout << "payload: [" << endl;
	for(size_t i = 0; i < payload.size(); i++) cout << static_cast<unsigned int>(payload[i]) << " ";
	cout << " ]" << endl;
	cout << "----------------------" << endl;

}

uint32_t TcpPacket::getSegSize(){
  return payload.size() + getFlag(TcpPacketFlags::SYN) + getFlag(TcpPacketFlags::FIN);
}

uint16_t TcpPacket::getChecksum(){
  return checksum;
}

TcpPacket& TcpPacket::setSrcPort(uint16_t source){
  sourcePort = source;
  return *this;
}
TcpPacket& TcpPacket::setDestPort(uint16_t dest){
  destPort = dest;
  return *this;
}
TcpPacket& TcpPacket::setSeq(uint32_t seq){
  seqNum = seq;
  return *this;
}
TcpPacket& TcpPacket::setAck(uint32_t ack){
  ackNum = ack;
  return *this;
}
TcpPacket& TcpPacket::setDataOffset(uint8_t dataOffset){
  dataOffReserved = (dataOffReserved & 0x0f) | ((dataOffset & 0xf) << 4);
  return *this;
}
TcpPacket& TcpPacket::setReserved(uint8_t reserved){
  dataOffReserved = (dataOffReserved & 0xf0) | (reserved & 0xf);
  return *this;
}
TcpPacket& TcpPacket::setWindow(uint16_t win){
  window = win;
  return *this;
}
TcpPacket& TcpPacket::setChecksum(uint16_t check){
  checksum = check;
  return *this;
}
TcpPacket& TcpPacket::setUrgentPointer(uint16_t urg){
  urgPointer = urg;
  return *this;
} 
TcpPacket& TcpPacket::setOptions(vector<TcpOption> list){
  optionList = list;
  size = calcSize();
  return *this;
}
TcpPacket& TcpPacket::setPayload(vector<uint8_t> data){
  payload = data;
  size = calcSize();
  return *this;
}

void TcpPacket::toBuffer(vector<uint8_t>& buff){

        loadBytes<uint16_t>(toAltOrder<uint16_t>(sourcePort), buff);
	loadBytes<uint16_t>(toAltOrder<uint16_t>(destPort), buff);
        loadBytes<uint32_t>(toAltOrder<uint32_t>(seqNum), buff);  
        loadBytes<uint32_t>(toAltOrder<uint32_t>(ackNum), buff);

	buff.push_back(dataOffReserved);
	buff.push_back(flags);
	
	loadBytes<uint16_t>(toAltOrder<uint16_t>(window), buff);
	loadBytes<uint16_t>(toAltOrder<uint16_t>(checksum), buff);
	loadBytes<uint16_t>(toAltOrder<uint16_t>(urgPointer), buff);
	
	for(size_t i = 0; i < optionList.size(); i++) optionList[i].toBuffer(buff);
	for(size_t i = 0; i < payload.size(); i++) buff.push_back(payload[i]);
}

TcpPacketCode TcpPacket::fromBuffer(uint8_t* buffer, int numBytes){
  
  if(numBytes < TCP_MIN_HEADER_LEN){
    return TcpPacketCode::HEADER;
  }

  sourcePort = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,0));
  destPort = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,2));
  seqNum = toAltOrder<uint32_t>(unloadBytes<uint32_t>(buffer,4));
  ackNum = toAltOrder<uint32_t>(unloadBytes<uint32_t>(buffer,8));
  dataOffReserved = buffer[12];
  flags = buffer[13];
  window = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,14));
  checksum = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,16));
  urgPointer = toAltOrder<uint16_t>(unloadBytes<uint16_t>(buffer,18));

  uint8_t offsetConv = getDataOffset() * 4;
  if(offsetConv < 20 || offsetConv > numBytes) return TcpPacketCode::HEADER;
  
  uint8_t* currPointer = buffer + TCP_MIN_HEADER_LEN;
  
  vector<TcpOption> options;
  
  if(offsetConv > TCP_MIN_HEADER_LEN){
    int optionBytesRemaining = offsetConv - TCP_MIN_HEADER_LEN;
    while(optionBytesRemaining > 0){
        TcpOption o;
        int numBytesRead = 0;
        bool rs = o.fromBuffer(currPointer, optionBytesRemaining, numBytesRead);
        if(!rs) return TcpPacketCode::OPTIONS;
        currPointer = currPointer + numBytesRead;
        optionBytesRemaining = optionBytesRemaining - numBytesRead;
        options.push_back(o);
    }
    optionList = options;
  }
  
  int dataBytesRemaining = numBytes - offsetConv;
  
  for(int i =0; i < dataBytesRemaining; i++){
    payload.push_back(currPointer[i]);
  }
  
  size = calcSize();

  return TcpPacketCode::SUCCESS;
}








