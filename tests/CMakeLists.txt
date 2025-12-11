cmake_minimum_required(VERSION 3.14)
project(my_project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
	googletest
	URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(
	allTests
	testTcpPacket.cc
	testIpPacket.cc
	testTcpIpPacket.cc
	testOpen.cc
	testClose.cc
	testAbort.cc
	testSendAndPackageSegment.cc
	../src/driver.cpp
	../src/tcpPacket.cpp
	../src/ipPacket.cpp
	../src/state.cpp
	../src/network.cpp
	testingUtil.cpp
)
add_definitions(-DTEST_NO_SEND=1)

target_link_libraries(
	allTests
	crypto
	ssl
	GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(allTests)
