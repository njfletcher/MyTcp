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
    
    //check send data and other async tasks
  
  }
  
  return LocalCode::Success;
}
