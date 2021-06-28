/* 
 * This file is part of the pebil project.
 * 
 * Copyright (c) 2010, University of California Regents
 * All rights reserved.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

void DynamicInstrumentation::InitializeDynamicInstrumentation(uint64_t* count, 
  DynamicInst** dyn, bool* isThreadedModeFlag) {
    assert(Dynamics != NULL);
    ThreadedMode = (*isThreadedModeFlag);


    DynamicInst* dd = *dyn;
    for (uint32_t i = 0; i < *count; i++){
        if (dd[i].IsEnabled){
            assert(dd[i].IsEnabled);
            uint64_t k = dd[i].Key;
            if (Dynamics->count(k) == 0){
                (*Dynamics)[k] = vector<DynamicInst*>();
            }
            (*Dynamics)[k].push_back(&dd[i]);
        }
    }
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

