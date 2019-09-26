#include <DynamicInstrumentation.hpp>
#include <Metasim.hpp>

#include <cassert>
#include <cstring>

static pebil_map_type < uint64_t, std::vector < DynamicInst* > > * Dynamics = 
  NULL;
static bool ThreadedModeFlag;

void PrintDynamicPoint(DynamicInst* d) {
    std::cout
        << "\t"
        << "\t" << "Key 0x" << std::hex << d->Key
        << "\t" << "Vaddr 0x" << std::hex << d->VirtualAddress
        << "\t" << "Oaddr 0x" << std::hex << d->ProgramAddress
        << "\t" << "Size " << std::dec << d->Size
        << "\t" << "Enabled " << (d->IsEnabled? "yes":"no")
        << "\n";
}

void InitializeDynamicInstrumentation(uint64_t* count, DynamicInst** dyn, 
  bool* isThreadedModeFlag) {
    if (Dynamics == NULL){
        Dynamics = new pebil_map_type < uint64_t, std::vector < DynamicInst* > > ();
    }
    assert(Dynamics != NULL);
    ThreadedModeFlag=(*isThreadedModeFlag);


    DynamicInst* dd = *dyn;
    for (uint32_t i = 0; i < *count; i++){
        if (dd[i].IsEnabled){
            assert(dd[i].IsEnabled);
            uint64_t k = dd[i].Key;
            if (Dynamics->count(k) == 0){
                (*Dynamics)[k] = std::vector<DynamicInst*>();
            }
            (*Dynamics)[k].push_back(&dd[i]);
        }
    }
}

void GetAllDynamicKeys(std::set<uint64_t>& keys) {
    assert(keys.size() == 0);
    for (pebil_map_type<uint64_t, std::vector<DynamicInst*> >::iterator it = 
      Dynamics->begin(); it != Dynamics->end(); it++){
        uint64_t k = (*it).first;
        keys.insert(k);
    }
}

void SetDynamicPointStatus(DynamicInst* d, bool state) {

    uint8_t t[DYNAMIC_POINT_SIZE_LIMIT];
    memcpy(t, (uint8_t*)d->VirtualAddress, d->Size);
    memcpy((uint8_t*)d->VirtualAddress, d->OppContent, d->Size);
    memcpy(d->OppContent, t, d->Size);

    d->IsEnabled = state;
    //PrintDynamicPoint(d);
}

void SetDynamicPoints(std::set<uint64_t>& keys, bool state) {
    uint32_t count = 0;
    for (pebil_map_type<uint64_t, std::vector<DynamicInst*> >::iterator it = 
      Dynamics->begin(); it != Dynamics->end(); it++){
        uint64_t k = (*it).first;
        if (keys.count(k) > 0){
            std::vector<DynamicInst*> dyns = (*it).second;
            for (std::vector<DynamicInst*>::iterator dit = dyns.begin(); dit != 
              dyns.end(); dit++){
                DynamicInst* d = (*dit);
                if (state != d->IsEnabled){
                    count++;
                    SetDynamicPointStatus(d, state);
                }
            }
        }
    }
    debug(std::cout << "Thread " << std::hex << pthread_self() << " switched " 
      << std::dec << count << " to " << (state? "on" : "off") << std::endl);
}

//Mostly needs to be static value?
bool isThreadedMode() {
    return ThreadedModeFlag;
}

