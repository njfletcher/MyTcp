#define assert(call, errorMsg) \
  if(!(call)){\
    cout << errorMsg << endl;\
    return false;\
  }\
  
#define test(call) \
  totalTests++; \
  if(call){\
      testsPassed++;\
      cout << "PASSED" << endl;\
  }\
  else{\
      cout << "FAILED" << endl;\
  }\
  
