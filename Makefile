
fuzzer: prog.o packet.o state.o network.o
	g++ -g prog.o packet.o state.o network.o -o fuzzer -lcrypto -lssl
prog.o: prog.cpp
	g++ -g -c prog.cpp
packet.o: packet.cpp
	g++ -g -c packet.cpp
state.o: state.cpp
	g++ -g -c state.cpp
network.o: network.cpp
	g++ -g -c network.cpp
clean:
	rm *.o fuzzer
