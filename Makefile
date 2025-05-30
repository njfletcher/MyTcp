
fuzzer: prog.o packet.o state.o network.o
	g++ prog.o packet.o state.o network.o -o fuzzer
prog.o: prog.cpp
	g++ -c prog.cpp
packet.o: packet.cpp
	g++ -c packet.cpp
state.o: state.cpp
	g++ -c state.cpp
network.o: network.cpp
	g++ -c network.cpp
	
clean:
	rm *.o fuzzer
