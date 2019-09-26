#ifndef _DynamicInstrumentation_hpp_
#define _DynamicInstrumentation_hpp_

#include <cstdint>
#include <vector>
#include <set>

#ifdef HAVE_UNORDERED_MAP
#include <tr1/unordered_map>
#define pebil_map_type std::tr1::unordered_map
#else
#include <map>
#define pebil_map_type std::map
#endif

typedef struct DynamicInst_s DynamicInst;

void PrintDynamicPoint(DynamicInst* d); 
void InitializeDynamicInstrumentation(uint64_t* count, DynamicInst** dyn,bool* isThreadedModeFlag);
void GetAllDynamicKeys(std::set<uint64_t>& keys);
void SetDynamicPointStatus(DynamicInst* d, bool state);
void SetDynamicPoints(std::set<uint64_t>& keys, bool state);
bool isThreadedMode();

#endif // _DynamicInstrumentation_hpp_
