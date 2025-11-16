#include "driver.h"
#include "state.h"
#include <poll.h>
#include <climits>
#include "ipPacket.h"
#include "tcpPacket.h"
#include <cstdint>
#include "network.h"

/*
multiplexIncoming-
Upon notification of incoming packet on interface, this method
checks details of the packet and gives it to correct connection, or sends reset if it does not belong
to a valid connection
*/

LocalCode multiplexIncoming(int socket, RemoteCode& remCode){

  IpPacket retPacket;
  SegmentEv ev;
  ev.ipPacket = retPacket;
  
  IpPacketCode pCode = IpPacketCode::Success;
  bool goodRec = recPacket(socket,retPacket, pCode);
  if(!goodRec){
    return LocalCode::Socket;
  }
  if(pCode == IpPacketCode::Success){
    TcpPacket& p = retPacket.tcpPacket;
    uint32_t sourceAddress = retPacket.getDestAddr();
    uint32_t destAddress = retPacket.getSrcAddr();
    uint16_t sourcePort = p.getDestPort();
    uint16_t destPort = p.getSrcPort();
    
    //drop the packet, unspec values are invalid
    if(sourceAddress == Unspecified || destAddress == Unspecified || sourcePort == Unspecified || destPort == Unspecified){
      remCode = RemoteCode::MalformedPacket;
      return LocalCode::Success;
    }
    
    LocalPair lP(sourceAddress, sourcePort);
    RemotePair rP(destAddress, destPort);
    
    ConnPair cPair(lP,rP);
    if(connections.find(cPair) != connections.end()){
      return connections[cPair].currentState->processEvent(socket,connections[cPair] ,ev, remCode);
    }
    RemotePair addrUnspec(Unspecified, rP.second);
    cPair.second = addrUnspec;
    if(connections.find(cPair) != connections.end()){
      return connections[cPair].currentState->processEvent(socket,connections[cPair],ev, remCode);
    }
    RemotePair portUnspec(rP.first, Unspecified);
    cPair.second = portUnspec;
    if(connections.find(cPair) != connections.end() ){
      return connections[cPair].currentState->processEvent(socket,connections[cPair],ev, remCode);
    }
    RemotePair fullUnspec(Unspecified, Unspecified);
    cPair.second = fullUnspec;
    if(connections.find(cPair) != connections.end()){
      return connections[cPair].currentState->processEvent(socket,connections[cPair],ev, remCode);
    }
    
    
    //if we've gotten to this point no conn exists: fictional closed state
    bool sent = false;
    if(!p.getFlag(TcpPacketFlags::rst)){
      if(p.getFlag(TcpPacketFlags::ack)){
        sent = sendReset(socket, lP, rP, 0, false, p.getAckNum());
      }
      else{
        sent = sendReset(socket, lP, rP, p.getSeqNum() + p.getSegSize(),true,0);
      }
    }
    
    remCode = RemoteCode::UnexpectedPacket;
    if(!sent) return LocalCode::Socket;
    else return LocalCode::Success;
    
  }
  else{
    
    //only send a reset if something related to tcp was malformed.
    //If something related to ip is malformed, we never got to parsing the tcp segment so theres no point in even trying to send a reset
    //Ideally this will always be an error with tcp and not ip because the kernel checks before passing to the raw socket should drop the packet.
    if(pCode == IpPacketCode::Payload){
      TcpPacket& p = retPacket.tcpPacket;
      uint32_t sourceAddress = retPacket.getDestAddr();
      uint32_t destAddress = retPacket.getSrcAddr();
      uint16_t sourcePort = p.getDestPort();
      uint16_t destPort = p.getSrcPort();
    
      //either we didnt even get to parse the address info, or we did and it is invalid. Either way can't send a reset.
      if(sourceAddress == Unspecified || destAddress == Unspecified || sourcePort == Unspecified || destPort == Unspecified){
        remCode = RemoteCode::MalformedPacket;
        return LocalCode::Success;
      }
    
      LocalPair lP(sourceAddress, sourcePort);
      RemotePair rP(destAddress, destPort);
      bool sent = false;
      if(!p.getFlag(TcpPacketFlags::rst)){
        if(p.getFlag(TcpPacketFlags::ack)){
          sent = sendReset(socket, lP, rP, 0, false, p.getAckNum());
        }
        else{
          sent = sendReset(socket, lP, rP, p.getSeqNum() + p.getSegSize(),true,0);
        }
      
      }
      
      remCode = RemoteCode::MalformedPacket;
      if(!sent) return LocalCode::Socket;
      else return LocalCode::Success;
    }
    
    remCode = RemoteCode::MalformedPacket;
    return LocalCode::Success;
  }
  
}


//effective send mss: how much tcp data are we actually allowed to send to the peer.
uint32_t getEffectiveSendMss(Tcb& b, vector<TcpOption> optionList){

  uint32_t optionListByteCount = 0;
  for(auto i = optionList.begin(); i < optionList.end(); i++){
    TcpOption o = *i;
    optionListByteCount++; //kind byte
    if(o.hasLength){
      optionListByteCount++;
    }
    optionListByteCount += o.data.size();
    
  }

  uint32_t messageSize = b.peerMss + tcpMinHeaderLen;
  uint32_t mmsS = getMmsS();
  if(mmsS < messageSize) messageSize = mmsS;
  
  return messageSize - optionListByteCount - tcpMinHeaderLen; //ipOptionByteCount is not considered because we are not setting any ip options on the raw socket.
}


//keep packaging send event data chunks into the segment until the segment needs to be sent
LocalCode packageAndSendSegment(int socket, Tcb& b, TcpPacket& sendPacket, int& numBytes, uint32_t effSendMss){

    bool packageMoreChunks = true;
    while(packageMoreChunks){
      SendEv& ev = b.sendQueue.front();
    
      //cant append urgent data after non urgent data: the urgent pointer will claim all the data is urgent when it is not
      if(ev.urgent && (!sendPacket.getFlag(TcpPacketFlags::urg) && (sendPacket.payload.size() > 0))){
          //send finished packet
          bool ls = sendDataPacket(socket,b,sendPacket);
          if(!ls){
              return LocalCode::Socket;
          }
          return LocalCode::Success;s
      }
     
     uint32_t bytesRead = ev.bytesRead;
     uint32_t dataRoom = static_cast<uint32_t>(ev.data.size()) - bytesRead;
     uint32_t packetRoom = effSendMss - sendPacket.payload.size();
     uint32_t upperBound = min({packetRoom, dataRoom, numBytes});
     for(uint32_t i = 0; i < upperBound; i++){
        sendPacket.payload.push_back(ev.data[bytesRead+i]);
        b.sNxt++;
        bytesRead++;
        numBytes--;
     }

     bool sendFin = false;
     if(ev.urgent){
      sendPacket.setFlag(TcpPacketFlags::urg);
            sendPacket.setUrgentPointer(b.sNxt - sendPacket.getSeqNum() -1);
        }
        if(upperBound == dataRoom){
            
            b.sendQueue.pop_front();
            b.sendQueueByteCount -= ev.data.size();
            if(b.sendQueue.empty() && !(b.closeQueue.empty())){
              sendFin = true;
            }
        }
        else{
            ev.bytesRead = bytesRead;
        }
          
        //peers window is filled up, sending more data would just get it rejected or dropped.
        //there might be partial data left in this data send buffer chunk
        if(upperBound == windowRoom){
            sendMorePackets = false;
            cont = false;
            bool ls = sendDataPacket(socket,b,sendPacket); 
            if(!ls){
                return LocalCode::Socket;
            }
            sendPacket = TcpPacket{};
            sendPacket.setSeq(b.sNxt);
              
        }
        else{
            if(upperBound == packetRoom){
                if(sendFin) sendPacket.setFlag(TcpPacketFlags::fin);
                bool ls = sendDataPacket(socket,b,sendPacket);
                if(!ls){
                  return LocalCode::Socket;
                }
                sendPacket = TcpPacket{};
                sendPacket.setSeq(b.sNxt);
            }
              
          
        }

    }

    return LocalCode::Success;

}

//keep packaging and sending segments until we've covered the specified number of bytes
LocalCode packageAndSendSegments(int socket, Tcb& b, int numBytes, uint32_t effSendMss){

  while(numBytes > 0){
      TcpPacket sendPacket;
      sendPacket.setSeq(b.sNxt);
      LocalCode ls = packageAndSendSegment(socket, b, sendPacket, numBytes, effSendMss);
      if(ls != LocalCode::Success){
          return ls;
      }
  }
        
}


LocalCode trySend(int socket, Tcb& b){

  bool sendMoreData = true;
  while(sendMoreData){
  
    uint32_t effSendMss = getEffectiveSendMss(b, vector<TcpOption>{});
    uint32_t usableWindow = b.sUna + b.sWnd - b.sNxt; 
    uint32_t minDu = usableWindow;
    if(b.sendQueueByteCount < usableWindow) minDu = b.sendQueueByteCount;
  
    if(minDu >= effSendMss){
      LocalCode lc = segmentAndSend(socket, Tcb& b, effSendMss, effSendMss);
      if(lc != LocalCode::Success) return lc;s
    }
    
    
    
    
  }
  

}



void tryConnectionSends(int socket){

  for(auto iter = connections.begin(); iter < connections.end(); iter++){
    Tcb& b = connections->second;
    checkSend(b);
  }
  
}



/*
entryTcp-
Starts the tcp implementation, equivalent to a tcp module being loaded.
in the future bind this to all available source addresses and poll all of them, not just one address
*/
LocalCode entryTcp(char* sourceAddr){

  uint32_t sourceAddress = toAltOrder<uint32_t>(inet_addr(sourceAddr));
  int socket = 0;
  bool worked =  bindSocket(sourceAddress, socket);
  if(!worked){
    return LocalCode::Socket;
  }
  
  RemoteCode remCode = RemoteCode::Success;
  struct pollfd pollItem;
  pollItem.fd = socket;
  pollItem.events = POLLIN; //read
  while(true){
  
    int numRet = poll(&pollItem, 1, -1);
    if((numRet > 0) && (pollItem.revents & POLLIN)){
      multiplexIncoming(socket, remCode);
    }
      
    tryConnectionSends(socket);
  
  }
  
  return LocalCode::Success;
}
