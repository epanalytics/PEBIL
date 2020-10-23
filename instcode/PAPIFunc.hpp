
#ifndef _PAPIFunc_hpp_
#define _PAPIFunc_hpp_

#include <sys/socket.h>
#include <sys/un.h>
#include <string>

#define MAX_HWC 32

#define KILO (1024)
#define MEGA (KILO*KILO)
#define GIGA (MEGA*KILO)

typedef long long values_t[MAX_HWC];

typedef struct {
  bool master;
  char* application;
  char* extension;
  uint64_t functionCount;
  char** functionNames;
  uint64_t* functionHashes;
  uint64_t* functionTimerAccum;
  uint64_t* functionTimerLast;
  uint64_t* functionEntryCounts;
  uint32_t* functionShutoff;
  uint32_t* inFunctionP;
  int events[MAX_HWC];
  values_t* tmpValues;
  values_t* accumValues;
  int num;
  int papiMeasurementsStarted;
  int currentlyMeasuring;
  int eventSet;
  int eventCode;
  std::set<int> activeFunctions;
} FunctionPAPI;

static char ToLowerCase(char c);
static bool ParsePositiveInt32(string token, uint32_t* value);
static bool ParseInt32(string token, uint32_t* value, uint32_t min);
static bool ParsePositiveInt32Hex(string token, uint32_t* value);
static bool ReadEnvUint32(string name, uint32_t* var);

#endif
