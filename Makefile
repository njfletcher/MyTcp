
fuzzer: prog.o packet.o
	g++ prog.o packet.o -o fuzzer
prog.o: prog.cpp
	g++ -c prog.cpp
packet.o: packet.cpp
	g++ -c packet.cpp
