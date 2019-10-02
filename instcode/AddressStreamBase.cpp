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

using namespace std;

SamplingMethod::SamplingMethod(uint32_t limit, uint32_t on, uint32_t off){
    AccessLimit = limit;
    SampleOn = on;
    SampleOff = off;

    AccessCount = 0;
}

SamplingMethod::~SamplingMethod(){
}

void SamplingMethod::Print(){
    inform << "SamplingMethod:" << TAB << "AccessLimit " << AccessLimit << " SampleOn " << SampleOn << " SampleOff " << SampleOff << ENDL;
}

void SamplingMethod::IncrementAccessCount(uint64_t count){
    AccessCount += count;
}

bool SamplingMethod::SwitchesMode(uint64_t count){
    return (CurrentlySampling(0) != CurrentlySampling(count));
}

bool SamplingMethod::CurrentlySampling(){
    return CurrentlySampling(0);
}

bool SamplingMethod::CurrentlySampling(uint64_t count){
    uint32_t PeriodLength = SampleOn + SampleOff;

    bool res = false;
    if (SampleOn == 0){
        return res;
    }

    if (PeriodLength == 0){
        res = true;
    }
    if ((AccessCount + count) % PeriodLength < SampleOn){
        res = true;
    }
    return res;
}

bool SamplingMethod::ExceedsAccessLimit(uint64_t count){
    bool res = false;
    if (AccessLimit > 0 && count > AccessLimit){
        res = true;
    }
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


// Common Functions
bool IsEmptyComment(string str){
    if (str == ""){
        return true;
    }
    if (str.compare(0, 1, "#") == 0){
        return true;
    }
    return false;
}


char ToLowerCase(char c){
    if (c < 'a'){
        c += ('a' - 'A');
    }
    return c;
}

// returns true on success... allows things to continue on failure if desired
bool ParseInt32(string token, uint32_t* value, uint32_t min){
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

bool ParsePositiveInt32(string token, uint32_t* value){
    return ParseInt32(token, value, 1);
}

uint32_t RandomInt(uint32_t max){
    return rand() % max;
}

bool ReadEnvUint32(string name, uint32_t* var){
    char* e = getenv(name.c_str());
    if (e == NULL){
        debug(inform << "unable to find " << name << " in environment" << ENDL;)
        return false;
    }
    string s (e);
    if (!ParseInt32(s, var, 0)){
        debug(inform << "unable to parse " << name << " in environment" <<
          ENDL;)
        return false;
    }
    return true;
}

