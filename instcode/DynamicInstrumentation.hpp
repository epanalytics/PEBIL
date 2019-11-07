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

class DynamicInstrumentation {
  protected:
    pebil_map_type < uint64_t, std::vector < DynamicInst* > > * Dynamics;
    bool ThreadedMode;
    
  public:
    DynamicInstrumentation();
    virtual ~DynamicInstrumentation();

    virtual void GetAllDynamicKeys(std::set<uint64_t>& keys);
    void InitializeDynamicInstrumentation(uint64_t* count, DynamicInst** dyn,
      bool* isThreadedModeFlag);
    bool IsThreadedMode() { return ThreadedMode; }

    void PrintAllDynamicPoints(); 
    void PrintDynamicPoint(DynamicInst* d); 
    void SetDynamicPointStatus(DynamicInst* d, bool state);
    virtual void SetDynamicPoint(uint64_t key, bool state);
    virtual void SetDynamicPoints(std::set<uint64_t>& keys, bool state);
    
    
};

#endif // _DynamicInstrumentation_hpp_
