/* 
 * This file is part of the pebil project.
 * 
 * Copyright (c) 2012, University of California Regents
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

#ifndef _CounterFunctions_hpp_
#define _CounterFunctions_hpp_

#include <Metasim.hpp>

typedef struct {
    bool Initialized;
    bool PerInstruction;
    bool Master;
    uint32_t Size;
    thread_key_t threadid;
    image_key_t imageid;
    uint64_t* Counters;
    CounterTypes* Types;
    uint64_t* Addresses;
    uint64_t* Hashes;
    uint32_t* Lines;
    uint32_t* BlockIds; // Block IDs and Loop IDs (sequence #)
    char** Files;
    char** Functions;
    char* Application;
    char* Extension;
    bool sanitize;
} CounterArray;

CounterArray* GenerateCounterArray(CounterArray* ctrs, uint32_t typ,
  image_key_t iid, thread_key_t tid, image_key_t firstimage);
uint64_t RefCounterArray(CounterArray* ctrs);
void DeleteCounterArray(CounterArray* ctrs);

// For testing only
class DynamicInstrumentation;
template <class T> class DataManager;
void InitializeAllData(DataManager<CounterArray*>* d);
void InitializeDynamicInstrumentation(DynamicInstrumentation* p);
DataManager<CounterArray*>* GetAllData();
DynamicInstrumentation* GetDynamicInstrumentation();

#endif //_CounterFunctions_hpp_
