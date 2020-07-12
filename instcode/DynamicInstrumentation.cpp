#include <DynamicInstrumentation.hpp>
#include <Metasim.hpp>

#include <cassert>
#include <cstring>

using namespace std;

DynamicInstrumentation::DynamicInstrumentation() : ThreadedMode(false) {
    Dynamics = new pebil_map_type < uint64_t, vector < DynamicInst* > > ();
}

DynamicInstrumentation::~DynamicInstrumentation() {
    // DynamicInst objects SHOULD be within binary so no need to manage them?
    Dynamics->clear();
    delete Dynamics;
}

void DynamicInstrumentation::GetAllDynamicKeys(set<uint64_t>& keys) {
    assert(keys.size() == 0);
    for (pebil_map_type<uint64_t, vector<DynamicInst*> >::iterator it = 
      Dynamics->begin(); it != Dynamics->end(); it++){
        uint64_t k = (*it).first;
        keys.insert(k);
    }
}

// NOTE: This function must be called within a mutex because of imageid
void DynamicInstrumentation::InitializeDynamicInstrumentation(uint64_t* count, 
  DynamicInst** dyn, bool* isThreadedModeFlag) {
    assert(Dynamics != NULL);

    if (InitializedDynamics.count(dyn) > 0)
        return;


    ThreadedMode = (*isThreadedModeFlag);
    static uint32_t imageId = 0;
    InitializedDynamics.insert(dyn);

    DynamicInst* dd = *dyn;
    for (uint32_t i = 0; i < *count; i++){
        if (dd[i].IsEnabled){
            assert(dd[i].IsEnabled);
            uint64_t k = dd[i].Key;
            uint32_t type = GET_TYPE(k);
            // Add the image id to the key if it uses one of our types
            if (type != PointType_inits) {
                uint64_t blockid = GET_BLOCKID(k);
                uint32_t type = GET_TYPE(k);
                k = GENERATE_UNIQUE_KEY(blockid, imageId, type);
                dd[i].Key = k;
            }
            if (Dynamics->count(k) == 0){
                (*Dynamics)[k] = vector<DynamicInst*>();
            }
            (*Dynamics)[k].push_back(&dd[i]);
        }
    }

    imageId++;
}

void DynamicInstrumentation::PrintAllDynamicPoints() {
    for (pebil_map_type<uint64_t, vector<DynamicInst*> >::iterator it = 
      Dynamics->begin(); it != Dynamics->end(); it++){
        uint64_t k = (*it).first;
        for (int i = 0; i < ((*Dynamics)[k].size()); i++) {
            PrintDynamicPoint((*Dynamics)[k].at(i));
        }
    }
}

void DynamicInstrumentation::PrintDynamicPoint(DynamicInst* d) {
    cout
        << "\t" << "Key 0x" << std::hex << d->Key
        << "\t" << "Vaddr 0x" << std::hex << d->VirtualAddress
        << "\t" << "Oaddr 0x" << std::hex << d->ProgramAddress
        << "\t" << "Size " << std::dec << d->Size
        << "\t" << "Enabled " << (d->IsEnabled? "yes":"no")
        << "\n";
}

void DynamicInstrumentation::PrintDynamicPoint(uint64_t key) {
    pebil_map_type < uint64_t, vector<DynamicInst*> >::iterator mit;
    mit = Dynamics->find(key);
    if (mit != Dynamics->end()) {
        vector<DynamicInst*> dyns = mit->second;
        for (vector<DynamicInst*>::iterator dit = dyns.begin(); dit != 
          dyns.end(); dit++){
            DynamicInst* d = (*dit);
            PrintDynamicPoint(d);
        }
    }
}

void DynamicInstrumentation::SetDynamicPointStatus(DynamicInst* d, bool state) {
    assert(state != d->IsEnabled);

    uint8_t t[DYNAMIC_POINT_SIZE_LIMIT];
    memcpy(t, (uint8_t*)d->VirtualAddress, d->Size);
    memcpy((uint8_t*)d->VirtualAddress, d->OppContent, d->Size);
    memcpy(d->OppContent, t, d->Size);

    d->IsEnabled = state;
}

void DynamicInstrumentation::SetDynamicPoint(uint64_t key, bool state) {
    pebil_map_type < uint64_t, vector<DynamicInst*> >::iterator mit;
    mit = Dynamics->find(key);
    if (mit != Dynamics->end()) {
        vector<DynamicInst*> dyns = mit->second;
        for (vector<DynamicInst*>::iterator dit = dyns.begin(); dit != 
          dyns.end(); dit++){
            DynamicInst* d = (*dit);
            if (state != d->IsEnabled){
                SetDynamicPointStatus(d, state);
            }
        }
    }
}

void DynamicInstrumentation::SetDynamicPoints(set<uint64_t>& keys, bool state) {
    for (set<uint64_t>::iterator it = keys.begin(); it != keys.end(); it++) {
        uint64_t k = (*it);
        SetDynamicPoint(k, state);
    }
    debug(cout << "Thread " << std::hex << pthread_self() << " switched " 
      << std::dec << keys.size() << " to " << (state? "on" : "off") 
      << std::endl);
}

