
test: tests/testConnections.cpp src/ipPacket.cpp src/tcpPacket.cpp src/state.cpp src/network.cpp
	g++ -g -DTEST_NO_SEND tests/testConnections.cpp src/state.cpp src/ipPacket.cpp src/tcpPacket.cpp src/network.cpp -o test -lcrypto -lssl
	
fuzzer: prog.o ipPacket.o tcpPacket.o state.o network.o
	g++ -g prog.o state.o ipPacket.o tcpPacket.o network.o -o fuzzer -lcrypto -lssl
prog.o: src/prog.cpp
	g++ -g -c src/prog.cpp
ipPacket.o: src/ipPacket.cpp
	g++ -g -c src/ipPacket.cpp
tcpPacket.o: src/tcpPacket.cpp
	g++ -g -c src/tcpPacket.cpp
state.o: src/state.cpp
	g++ -g -c src/state.cpp
network.o: src/network.cpp
	g++ -g -c src/network.cpp
clean:
	rm *.o fuzzer test
