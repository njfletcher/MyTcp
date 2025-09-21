
fuzzer: prog.o ipPacket.o tcpPacket.o state.o network.o
	g++ -g prog.o packet.o state.o network.o -o fuzzer -lcrypto -lssl
prog.o: prog.cpp
	g++ -g -c prog.cpp
ipPacket.o: ipPacket.cpp
	g++ -g -c ipPacket.cpp
tcpPacket.o: tcpPacket.cpp
	g++ -g -c tcpPacket.cpp
state.o: state.cpp
	g++ -g -c state.cpp
network.o: network.cpp
	g++ -g -c network.cpp
clean:
	rm *.o fuzzer
