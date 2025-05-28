#include "network.h"
#include "packet.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <iostream>
#include <arpa/inet.h>
    

using namespace std;

uint8_t ipBuffer[ipPacketMaxSize];

int sendPacket(char* destAddr, TcpPacket& p, IpPacket& packet){  
  
  	struct sockaddr_in dest;
	struct sockaddr_in serv;
	int s = socket(AF_INET, SOCK_RAW, TCP_PROTO);
	
	if(s < 0){
		perror("Cannot create socket. ");
		return -1;
	}
		
	dest.sin_family = AF_INET;
        dest.sin_port = htons(p.getDestPort());
        cout << destAddr << endl;
        inet_aton(destAddr, &(dest.sin_addr));
        
        serv.sin_family = AF_INET;
        serv.sin_port = htons(p.getSrcPort());
        serv.sin_addr.s_addr = INADDR_ANY;
                
	if(bind(s, (struct sockaddr* ) &serv, sizeof(serv)) != 0){
                
                perror("Cannot bind socket to server port. ");
         	return -1;     
        }
        
        vector<uint8_t> buffer;
        p.toBuffer(buffer);
        for(size_t i = 0; i < buffer.size(); i++){
          ipBuffer[i] = buffer[i];
        }
                        
        ssize_t numBytes = sendto(s, ipBuffer, buffer.size(), 0, (struct sockaddr*)&dest, sizeof(dest));
	
	if(numBytes < 0){
		perror("Cannot send message. ");
		return -1;
	}
	
	ssize_t numRec = recvfrom(s,ipBuffer,ipPacketMaxSize,0,nullptr, nullptr);
	
	if(numRec < 0){
		perror("Cannot receive message. ");
		return -1;
	}   
	
	int ret = packet.fromBuffer(ipBuffer, numRec);
	if(ret < 0){
	      perror("Bad packet. ");
	      return -1;
	}
	
	return 0;
}	
      	
      	
