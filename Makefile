
fuzzer: prog.o packet.o network.o
	g++ prog.o packet.o network.o -o fuzzer
prog.o: prog.cpp
	g++ -c prog.cpp
packet.o: packet.cpp
	g++ -c packet.cpp
network.o: network.cpp
	g++ -c network.cpp
