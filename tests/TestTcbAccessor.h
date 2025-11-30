#include <gtest/gtest.h>
#include "../src/state.h"


class TestTcbAccessor{

  public:
    static State& currentState(Tcb& b){ return *b.currentState; }

};
