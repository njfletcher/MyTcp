fuzzer: prog.o driver.o ipPacket.o tcpPacket.o state.o network.o
	g++ -g prog.o driver.o state.o ipPacket.o tcpPacket.o network.o -o fuzzer -lcrypto -lssl
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
driver.o: src/driver.cpp
	g++ -g -c src/driver.cpp
clean:
	rm *.o fuzzer test
