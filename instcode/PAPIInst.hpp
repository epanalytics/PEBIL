
#ifndef _PAPIInst_hpp_
#define _PAPIInst_hpp_

#include <sys/socket.h>
#include <sys/un.h>
#include <string>

using namespace std;

#define MAX_HWC 32

#define KILO (1024)
#define MEGA (KILO*KILO)
#define GIGA (MEGA*KILO)

typedef long long values_t[MAX_HWC];

typedef struct {
  bool master;
  char* application;
  char* extension;
  uint64_t loopCount;
  uint64_t* loopHashes;
  uint64_t* loopTimerAccum;
  uint64_t* loopTimerLast;
  int events[MAX_HWC];
  values_t* tmpValues;
  values_t* accumValues;
  int num;
  int papiMeasurementsStarted;
  int currentlyMeasuring;
  std::set<int> activeLoops;
} PAPIInst;

static char ToLowerCase(char c);
static bool ParsePositiveInt32(string token, uint32_t* value);
static bool ParseInt32(string token, uint32_t* value, uint32_t min);
static bool ParsePositiveInt32Hex(string token, uint32_t* value);
static bool ReadEnvUint32(string name, uint32_t* var);

#endif
