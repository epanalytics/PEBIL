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

#include <InstrumentationCommon.hpp>
#include <Metasim.hpp>
#include <AddressStreamBase.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cassert>
#include <utility>

using namespace std;

AddressStreamTool::~AddressStreamTool() {
    for (vector<MemoryStreamHandler*>::iterator it = handlers.begin(); it !=
      handlers.end(); it++) {
        delete (*it);
    }
    handlers.clear();
}

// Only one thread should construct a SamplingMethod at a time
SamplingMethod::SamplingMethod(uint32_t limit, uint32_t on, uint32_t off){
    AccessLimit = limit;
    SampleOn = on;
    SampleOff = off;

    AccessCount = 0;

    // Set to prefer to prevent starvation at thread initializeation
    pthread_rwlockattr_init(&sampling_rwlock_attr);
    pthread_rwlockattr_setkind_np(&sampling_rwlock_attr,
      PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    pthread_rwlock_init(&sampling_rwlock, &sampling_rwlock_attr);
}

SamplingMethod::~SamplingMethod(){
}

bool SamplingMethod::CurrentlySampling(){
    return CurrentlySampling(0);
}

// Returns if would be sampling after "count" samples
bool SamplingMethod::CurrentlySampling(uint64_t count){
    ReadLock();
    uint32_t PeriodLength = SampleOn + SampleOff;

    bool res = false;
    if (SampleOn == 0){
        UnLock();
        return res;
    }

    if (PeriodLength == 0){
        res = true;
    }

    if ((AccessCount + count) % PeriodLength < SampleOn){
        res = true;
    }
    
    UnLock();
    return res;
}

bool SamplingMethod::ExceedsAccessLimit(uint64_t count){
    ReadLock();
    bool res = false;
    if (AccessLimit > 0 && count > AccessLimit){
        res = true;
    }
    UnLock();
    return res;
}

double SamplingMethod::GetSamplingFrequency() {
    ReadLock();
    if (SampleOn == 0) {
        UnLock();
        return 0;
    }
    double frequency = (double)SampleOn / (double)(SampleOn + SampleOff);
    UnLock();
    return frequency;
}

void SamplingMethod::IncrementAccessCount(uint64_t count){
    WriteLock();
    AccessCount += count;
    UnLock();
}

bool SamplingMethod::SwitchesMode(uint64_t count){
    return (CurrentlySampling(0) != CurrentlySampling(count));
}

void SamplingMethod::Print(){
    ReadLock();
    inform << "SamplingMethod:" << TAB << "AccessLimit " << AccessLimit << " SampleOn " << SampleOn << " SampleOff " << SampleOff << ENDL;
    UnLock();
}

bool SamplingMethod::ReadLock() {
    bool res = (pthread_rwlock_rdlock(&sampling_rwlock) == 0);
    return res;
}

bool SamplingMethod::UnLock() {
    bool res = (pthread_rwlock_unlock(&sampling_rwlock) == 0);
    return res;
}

bool SamplingMethod::WriteLock() {
    bool res = (pthread_rwlock_wrlock(&sampling_rwlock) == 0);
    return res;
}

MemoryStreamHandler::MemoryStreamHandler(){
    pthread_mutex_init(&mlock, NULL);
}
MemoryStreamHandler::~MemoryStreamHandler(){
}

bool MemoryStreamHandler::TryLock(){
    return (pthread_mutex_trylock(&mlock) == 0);
}

bool MemoryStreamHandler::Lock(){
    return (pthread_mutex_lock(&mlock) == 0);
}

bool MemoryStreamHandler::UnLock(){
    return (pthread_mutex_unlock(&mlock) == 0);
}

char* StringParser::GetEnv(const char* variable){
	return getenv(variable);
}

bool StringParser::IsEmptyComment(string str){
    if (str == ""){
        return true;
    }
    if (str.compare(0, 1, "#") == 0){
        return true;
    }
    return false;
}

// returns true on success... allows things to continue on failure if desired
bool StringParser::ParseInt32(string token, int32_t* value, int32_t min){
    int32_t val;
    uint32_t mult = 1;
    bool ErrorFree = true;

    istringstream stream(token);
    if (stream >> val){
        if (!stream.eof()){
            char c;
            stream.get(c);

            c = ToLowerCase(c);
            if (c == 'k'){
                mult = KILO;
            } else if (c == 'm'){
                mult = MEGA;
            } else if (c == 'g'){
                mult = GIGA;
            } else {
                ErrorFree = false;
            }

            if (!stream.eof()){
                stream.get(c);

                c = ToLowerCase(c);
                if (c != 'b'){
                    ErrorFree = false;
                }
            }
        }
    }

    if (val < min){
        ErrorFree = false;
    }

    (*value) = (val * mult);
    return ErrorFree;
}

bool StringParser::ParsePositiveInt32(string token, uint32_t* value){
    bool ret = ParseInt32(token, (int32_t*)value, 1);
    assert((int32_t)(*value) == (uint32_t)(*value));
    return ret;
}

bool StringParser::ReadEnvUint32(string name, uint32_t* var){
    char* e = getenv(name.c_str());
    if (e == NULL){
        debug(inform << "unable to find " << name << " in environment" << ENDL;)
        return false;
    }
    string s (e);
    if (!ParseInt32(s, (int32_t*)var, 0)){
        debug(inform << "unable to parse " << name << " in environment" <<
          ENDL;)
        return false;
    }
    return true;
}

char StringParser::ToLowerCase(char c){
    if (c < 'a'){
        c += ('a' - 'A');
    }
    return c;
}

uint32_t Randomizer::RandomInt(uint32_t max){
    assert(max > 0 && "Cannot mod by 0");
    return rand() % max;
}

EasyHash::EasyHash(){
    internal_map = new pebil_map_type<uint32_t, uint32_t*>();
}

EasyHash::~EasyHash(){
    pebil_map_type<uint32_t, uint32_t*>::iterator it = internal_map->begin();
    pebil_map_type<uint32_t, uint32_t*>::iterator end = internal_map->end();
    while (it!=end){
        delete it->second;
        internal_map->erase(it);
        it++;
    }
    internal_map->clear();
    delete internal_map;
}

bool EasyHash::contains(uint32_t key){
    if ( internal_map->find(key) == internal_map->end() ){ //is not in map
        return false;
    } else {
        return true;
    }
}

void EasyHash::add(uint32_t key, uint32_t* toAdd){
    if (this->contains(key)){
        uint32_t* curVal = internal_map->find(key)->second;
        curVal[0] = curVal[0] + toAdd[0];
        curVal[1] = curVal[1] + toAdd[1];
        (*internal_map)[key] = curVal;
    } else {
        uint32_t* newToAdd = new uint32_t[2];
        newToAdd[0] = toAdd[0];
        newToAdd[1] = toAdd[1];
        std::pair<uint32_t,uint32_t*> kvp (key, newToAdd);
        internal_map->insert(kvp);
    }
}

uint32_t* EasyHash::get(uint32_t key, uint32_t* output){
    if (!this->contains(key)){
        output[0] = 0;
        output[1] = 0;
        return output;
    }
    return internal_map->find(key)->second;
}

NestedHash::NestedHash(){
    internal_hash = new pebil_map_type<uint32_t, EasyHash*>();
}

NestedHash::~NestedHash(){
    pebil_map_type<uint32_t, EasyHash*>::iterator it = internal_hash->begin();
    pebil_map_type<uint32_t, EasyHash*>::iterator end = internal_hash->end();
    while (it!=end){
        delete it->second;
        internal_hash->erase(it);
        it++;
    }
    internal_hash->clear();
    delete internal_hash;
}

bool NestedHash::contains(uint32_t set, uint32_t line){
    if( internal_hash->find(set) == internal_hash->end() ){
        return false;
    } else {
        EasyHash* oldHash = internal_hash->find(set)->second;
        return oldHash->contains(line);
    }
}

void NestedHash::put(uint32_t set, uint32_t line, uint32_t* value){
    if ( internal_hash->find(set) == internal_hash->end() ){ //no dictionary for this set yet
        EasyHash* newEasy = new EasyHash();
        newEasy->add(line, value);
        std::pair<uint32_t, EasyHash*> kvp (set, newEasy);
        internal_hash->insert(kvp);
    } else { // there is a dictionary present
        EasyHash* oldEasy = internal_hash->find(set)->second;
        oldEasy->add(line, value);
    }
}

uint32_t* NestedHash::get(uint32_t set, uint32_t line, uint32_t* output) {
    if(!this->contains(set, line)){
        output[0] = 0;
        output[1] = 0;
        return output;
    }
    EasyHash* oldHash = internal_hash->find(set)->second;
    return oldHash->get(line, output);
}

