#pragma once
#include <utility>
#include <cstdint>
#include <unordered_map>

typedef std::pair<uint32_t, uint16_t> LocalPair;
typedef std::pair<uint32_t, uint16_t> RemotePair;
typedef std::pair<LocalPair, RemotePair> ConnPair;

#include "state.h"

struct ConnHash{
  std::size_t operator()(const ConnPair& p) const;
};

typedef std::unordered_map<ConnPair, Tcb, ConnHash > ConnectionMap;
extern std::unordered_map<int, ConnPair> idMap;
extern ConnectionMap connections;

const uint16_t DYN_PORT_START = 49152;
const uint16_t DYN_PORT_END = 65535;

void reclaimId(int id);
uint16_t pickDynPort();
bool pickId(int& id);
uint32_t pickDynAddr();
void removeConn(Tcb& b);
LocalCode entryTcp(char* sourceAddr);
