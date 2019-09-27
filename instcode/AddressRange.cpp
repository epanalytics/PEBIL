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
#include <AddressRange.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cassert>

using namespace std;

void RangeFileName(AddressStreamStats* stats, string& oFile){
    oFile.clear();
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".");
    oFile.append("addrange");
}

RangeStats::RangeStats(uint32_t capacity){
    Capacity = capacity;
    Counts = new uint64_t[Capacity];
    bzero(Counts, sizeof(uint64_t) * Capacity);
    Ranges = new AddressRange*[Capacity];
    for (uint32_t i = 0; i < Capacity; i++){
        Ranges[i] = new AddressRange();
        Ranges[i]->Minimum = MAX_64BIT_VALUE;
        Ranges[i]->Maximum = 0;
    }
}

RangeStats::~RangeStats(){
    if (Ranges){
        delete[] Ranges;
    }
    if (Counts){
        delete[] Counts;
    }
}

bool RangeStats::HasMemId(uint32_t memid){
    return (memid < Capacity);
}

uint64_t RangeStats::GetMinimum(uint32_t memid){
    assert(HasMemId(memid));
    return Ranges[memid]->Minimum;
}

uint64_t RangeStats::GetMaximum(uint32_t memid){
    assert(HasMemId(memid));
    return Ranges[memid]->Maximum;
}

void RangeStats::Update(uint32_t memid, uint64_t addr){
    Update(memid, addr, 1);
}

void RangeStats::Update(uint32_t memid, uint64_t addr, uint32_t count){
    AddressRange* r = Ranges[memid];
    if (addr < r->Minimum){
        r->Minimum = addr;
    }
    if (addr > r->Maximum){
        r->Maximum = addr;
    }
    Counts[memid] += count;
}

bool RangeStats::Verify(){
    return true;
}

AddressRangeHandler::AddressRangeHandler(){
}
AddressRangeHandler::AddressRangeHandler(AddressRangeHandler& h){
    pthread_mutex_init(&mlock, NULL);
}
AddressRangeHandler::~AddressRangeHandler(){
}

void AddressRangeHandler::Print(ofstream& f){
    f << "AddressRangeHandler" << ENDL;
}

uint32_t AddressRangeHandler::Process(void* stats, BufferEntry* access){

    if(access->type == MEM_ENTRY) {
        uint32_t memid = (uint32_t)access->memseq;
        uint64_t addr = access->address;
        RangeStats* rs = (RangeStats*)stats;
        rs->Update(memid, addr);
        return 0;
    } else if(access->type == VECTOR_ENTRY) {
        uint64_t currAddr;
        uint32_t memid = (uint32_t)access->memseq;
        uint16_t mask = (access->vectorAddress).mask;
        RangeStats* rs = (RangeStats*)stats;

        for (int i = 0; i < (access->vectorAddress).numIndices; i++) {
            if(mask % 2 == 1) {
                currAddr = (access->vectorAddress).base + 
                  (access->vectorAddress).indexVector[i] * 
                  (access->vectorAddress).scale;
                rs->Update(memid, currAddr);
            }
            mask = (mask >> 1);
        }
        return 0;
    } 
    // TODO To be implemented later
    /*} else if(access->type == PREFETCH_ENTRY) {
        uint32_t memid = (uint32_t)access->memseq;
        uint64_t addr = access->address;
        if (ExecuteSoftwarePrefetches) {
          RangeStats* rs = (RangeStats*)stats;
          rs->Update(memid, addr);
        }
        return 0;
   }*/
}
                
