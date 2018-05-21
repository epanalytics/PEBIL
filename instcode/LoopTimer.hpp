
#ifndef _LoopTimers_hpp_
#define _LoopTimers_hpp_

#include <string>

using namespace std;

typedef struct {
    bool master;
    char* application;
    char* extension;
    uint64_t loopCount;
    uint64_t* loopHashes;
    uint64_t* loopTimerAccum;
    uint64_t* loopTimerLast;
    uint64_t* entryCounts;
} LoopTimers;

#define KILO (1024)
#define MEGA (KILO*KILO)
#define GIGA (MEGA*KILO)
static char ToLowerCase(char c);
static bool ParsePositiveInt32(string token, uint32_t* value);
static bool ParseInt32(string token, uint32_t* value, uint32_t min);
static bool ParsePositiveInt32Hex(string token, uint32_t* value);
static bool ReadEnvUint32(string name, uint32_t* var);


#endif
