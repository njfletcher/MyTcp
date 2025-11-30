#include "driver.h"
#include "state.h"
#include <poll.h>
#include <climits>
#include "ipPacket.h"
#include "tcpPacket.h"
#include <cstdint>
#include <queue>
#include "network.h"

using namespace std;

const uint32_t bestLocalAddr=1;

//range from dynPortStart to dynPortEnd
unordered_map<uint16_t,bool> usedPorts;

std::size_t ConnHash::operator()(const ConnPair& p) const {
  
  return std::hash<uint32_t>{}(p.first.first) ^
  (std::hash<uint16_t>{}(p.first.second) << 1) ^
  (std::hash<uint32_t>{}(p.second.first) << 2) ^
  (std::hash<uint16_t>{}(p.second.second) << 3);
}

std::unordered_map<int, ConnPair> idMap;
ConnectionMap connections;


//simulates passing a passing an info/error message to a hooked up application that is not applicable to a made connection.
void notifyApp(App* app, TcpCode c, uint32_t eId){
  app->getAppNotifs().push_back(c);
}

void notifyApp(App* app, int connId, TcpCode c, uint32_t eId){
  app->getConnNotifs()[connId].push_back(c);
}

/*pickDynPort 
picks an unused port from the dynamic range
if for some reason it cant find one, returns 0(unspecified)
the user should check for unspecified as an error
*/
uint16_t pickDynPort(){
  
  for(uint16_t p = DYN_PORT_START; p <= DYN_PORT_END; p++){
    if(usedPorts.find(p) == usedPorts.end()){
      usedPorts[p] = true;
      return p;
    }
  }
  return UNSPECIFIED;

}

/*pickId
picks an available id to map a connection to. 
returns bool specifying whether it worked or not
*/
bool pickId(int& id){
  for(int i = 0; i <= INT_MAX; i++){
    if(idMap.find(i) == idMap.end()){
      id = i;
      return true;
    }
  }
  return false;
}

/*
reclaimId
reclaims id so that it can be used with new connections
assumes the id is a valid one that is in use
*/
void reclaimId(int id){
  idMap.erase(id);
}

/*pickDynAddr
ideally will pick best address based on routing tables.
for right now this just returns a default address
*/
uint32_t pickDynAddr(){

  return bestLocalAddr;
}

void removeConn(Tcb& b){

  reclaimId(b.getId());
  connections.erase(b.getConnPair());
}

LocalCode remConnFlushAll(int socket, Tcb& b, Event& e){
  notifyApp(b.getParApp(), b.getId(),TcpCode::CONNRST, e.getId());
  removeConn(b);
  return LocalCode::SUCCESS;
  //TODO: flush segment queues and respond reset to outstanding receives and sends.

}
LocalCode remConnOnly(int socket, Tcb& b){
  removeConn(b);
  return LocalCode::SUCCESS;
}


/*
multiplexIncoming-
Upon notification of incoming packet on interface, this method
checks details of the packet and gives it to correct connection, or sends reset if it does not belong
to a valid connection
*/
LocalCode multiplexIncoming(int socket, RemoteCode& remCode){

  IpPacket retPacket;
  SegmentEv ev(retPacket,0);
  
  IpPacketCode pCode = IpPacketCode::SUCCESS;
  bool goodRec = recPacket(socket,retPacket, pCode);
  if(!goodRec){
    return LocalCode::SOCKET;
  }
  if(pCode == IpPacketCode::SUCCESS){
    TcpPacket& p = retPacket.getTcpPacket();
    uint32_t sourceAddress = retPacket.getDestAddr();
    uint32_t destAddress = retPacket.getSrcAddr();
    uint16_t sourcePort = p.getDestPort();
    uint16_t destPort = p.getSrcPort();
    
    //drop the packet, unspec values are invalid
    if(sourceAddress == UNSPECIFIED || destAddress == UNSPECIFIED || sourcePort == UNSPECIFIED || destPort == UNSPECIFIED){
      remCode = RemoteCode::MALFORMEDPACKET;
      return LocalCode::SUCCESS;
    }
    
    LocalPair lP(sourceAddress, sourcePort);
    RemotePair rP(destAddress, destPort);
    
    ConnPair cPair(lP,rP);
    if(connections.find(cPair) != connections.end()){
      return connections[cPair].processEventEntry(socket,ev, remCode);
    }
    RemotePair addrUnspec(UNSPECIFIED, rP.second);
    cPair.second = addrUnspec;
    if(connections.find(cPair) != connections.end()){
      return connections[cPair].processEventEntry(socket,ev, remCode);
    }
    RemotePair portUnspec(rP.first, UNSPECIFIED);
    cPair.second = portUnspec;
    if(connections.find(cPair) != connections.end() ){
      return connections[cPair].processEventEntry(socket,ev, remCode);
    }
    RemotePair fullUnspec(UNSPECIFIED, UNSPECIFIED);
    cPair.second = fullUnspec;
    if(connections.find(cPair) != connections.end()){
      return connections[cPair].processEventEntry(socket,ev, remCode);
    }
    
    
    //if we've gotten to this point no conn exists: fictional closed state
    bool sent = false;
    if(!p.getFlag(TcpPacketFlags::RST)){
      if(p.getFlag(TcpPacketFlags::ACK)){
        sent = Tcb::sendReset(socket, lP, rP, 0, false, p.getAckNum());
      }
      else{
        sent = Tcb::sendReset(socket, lP, rP, p.getSeqNum() + p.getSegSize(),true,0);
      }
    }
    
    remCode = RemoteCode::UNEXPECTEDPACKET;
    if(!sent) return LocalCode::SOCKET;
    else return LocalCode::SUCCESS;
    
  }
  else{
    
    //only send a reset if something related to tcp was malformed.
    //If something related to ip is malformed, we never got to parsing the tcp segment so theres no point in even trying to send a reset
    //Ideally this will always be an error with tcp and not ip because the kernel checks before passing to the raw socket should drop the packet.
    if(pCode == IpPacketCode::PAYLOAD){
      TcpPacket& p = retPacket.getTcpPacket();
      uint32_t sourceAddress = retPacket.getDestAddr();
      uint32_t destAddress = retPacket.getSrcAddr();
      uint16_t sourcePort = p.getDestPort();
      uint16_t destPort = p.getSrcPort();
    
      //either we didnt even get to parse the address info, or we did and it is invalid. Either way can't send a reset.
      if(sourceAddress == UNSPECIFIED || destAddress == UNSPECIFIED || sourcePort == UNSPECIFIED || destPort == UNSPECIFIED){
        remCode = RemoteCode::MALFORMEDPACKET;
        return LocalCode::SUCCESS;
      }
    
      LocalPair lP(sourceAddress, sourcePort);
      RemotePair rP(destAddress, destPort);
      bool sent = false;
      if(!p.getFlag(TcpPacketFlags::RST)){
        if(p.getFlag(TcpPacketFlags::ACK)){
          sent = Tcb::sendReset(socket, lP, rP, 0, false, p.getAckNum());
        }
        else{
          sent = Tcb::sendReset(socket, lP, rP, p.getSeqNum() + p.getSegSize(),true,0);
        }
      
      }
      
      remCode = RemoteCode::MALFORMEDPACKET;
      if(!sent) return LocalCode::SOCKET;
      else return LocalCode::SUCCESS;
    }
    
    remCode = RemoteCode::MALFORMEDPACKET;
    return LocalCode::SUCCESS;
  }
  
}


LocalCode tryConnectionSends(int socket){
  for(auto iter = connections.begin(); iter != connections.end(); iter++){
    Tcb& b = iter->second;
    LocalCode c = b.trySend(socket );
    if(c != LocalCode::SUCCESS) return c;
  }
  return LocalCode::SUCCESS;
}



LocalCode send(App* app, int socket, bool urgent, deque<uint8_t>& data, LocalPair lP, RemotePair rP, bool push, uint32_t timeout){

  SendEv ev(data,urgent,push,0);
  ConnPair p(lP,rP);
  
  if(connections.find(p) != connections.end()){
    Tcb& oldConn = connections[p];
    return oldConn.processEventEntry(socket, ev); 
  }  
  
  notifyApp(app,TcpCode::NOCONNEXISTS, ev.getId());
  return LocalCode::SUCCESS;

}

LocalCode receive(App* app, int socket, uint32_t amount, std::vector<uint8_t>& buff, LocalPair lP, RemotePair rP){

  ReceiveEv ev(amount, buff, 0);
 
  ConnPair p(lP, rP);
  if(connections.find(p) != connections.end()){
      Tcb& oldConn = connections[p];
      return oldConn.processEventEntry(socket, ev); 
  }  
  
  notifyApp(app, TcpCode::NOCONNEXISTS, ev.getId());
  return LocalCode::SUCCESS;

}

LocalCode close(App* app, int socket, LocalPair lP, RemotePair rP){

  CloseEv ev(0);
  
  ConnPair p(lP, rP);
  if(connections.find(p) != connections.end()){
      Tcb& oldConn = connections[p];
      return oldConn.processEventEntry(socket, ev); 
  }  
  
  notifyApp(app, TcpCode::NOCONNEXISTS, ev.getId());
  return LocalCode::SUCCESS;
}

LocalCode abort(App* app, int socket, LocalPair lP, RemotePair rP){

  AbortEv ev(0);
  
  ConnPair p(lP,rP);
  if(connections.find(p) != connections.end()){
      Tcb& oldConn = connections[p];
      return oldConn.processEventEntry(socket, ev); 
  }  
  
  notifyApp(app, TcpCode::NOCONNEXISTS, ev.getId());
  return LocalCode::SUCCESS;
}

/*
open-
Models an open event call from an app to a kernel.
AppId is an id that the simulated app registers with the kernel, createdId is populated with the id of the connection.
createdId should only be used if LocalCode::Success is returned and there are no app notifications indicating the connection failed
*/
LocalCode open(App* app, int socket, bool passive, LocalPair lP, RemotePair rP, int& createdId){

  OpenEv ev(passive,0);
  
  ConnPair p(lP,rP);
  if(connections.find(p) != connections.end()){
    //duplicate connection
    Tcb& oldConn = connections[p];
    return oldConn.processEventEntry(socket, ev);   
  }
  
  bool success = false;
  Tcb b = Tcb::buildTcbFromOpen(success, app, socket, lP, rP, createdId, ev);
  if(success) connections[p] = move(b);
  return LocalCode::SUCCESS;
  
}

/*
entryTcp-
Starts the tcp implementation, equivalent to a tcp module being loaded.
in the future bind this to all available source addresses and poll all of them, not just one address
*/
LocalCode entryTcp(char* sourceAddr){

  int socket = 0;
  bool worked = bindSocket(sourceAddr, socket);
  if(!worked){
    return LocalCode::SOCKET;
  }
  
  RemoteCode remCode = RemoteCode::SUCCESS;
  struct pollfd pollItem;
  pollItem.fd = socket;
  pollItem.events = POLLIN; //read
  while(true){
  
    int numRet = poll(&pollItem, 1, -1);
    if((numRet > 0) && (pollItem.revents & POLLIN)){
      multiplexIncoming(socket, remCode);
    }
      
    LocalCode c = tryConnectionSends(socket);
    if(c != LocalCode::SUCCESS) return c;
  
  }
  
  return LocalCode::SUCCESS;
  
}

