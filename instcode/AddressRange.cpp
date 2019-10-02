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
#include <DataManager.hpp>
#include <Metasim.hpp>
#include <AddressStreamBase.hpp>
#include <AddressRange.hpp>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cassert>

using namespace std;

void PrintRangeFile(DataManager<AddressStreamStats*>* AllData, SamplingMethod* 
  Sampler, int32_t rangeIndex) {
        AddressStreamStats* stats = AllData->GetData(*(AllData->allimages.begin()));
        // Create the Address Range report
        ofstream RangeFile;
        string oFile;
        const char* fileName;

        RangeFileName(stats,oFile);
        fileName=oFile.c_str();
        inform << "Printing address range results to " << fileName << ENDL;
        TryOpen(RangeFile,fileName);

        uint64_t sampledCount = 0;
        uint64_t totalMemop = 0;
        // Calculate the number of access counts
        for (set<image_key_t>::iterator iit = AllData->allimages.begin();
          iit != AllData->allimages.end(); iit++){

            for(DataManager<AddressStreamStats*>::iterator it =
              AllData->begin(*iit); it != AllData->end(*iit); ++it) {
                thread_key_t thread = it->first;
                AddressStreamStats* s = it->second;

                RangeStats* r = (RangeStats*)s->Stats[rangeIndex];
                assert(r);
                for (uint32_t i = 0; i < r->Capacity; i++){
                    sampledCount += r->Counts[i];
                }

                for (uint32_t i = 0; i < s->BlockCount; i++){
                    uint32_t idx;
                    // Don't need to do this loop if this block doesn't have
                    // any memops
                    if(s->MemopsPerBlock[i] == 0) {
                        continue;
                    }
                    if (s->Types[i] == CounterType_basicblock){
                        idx = i;
                    } else if (s->Types[i] == CounterType_instruction){
                        idx = s->Counters[i];
                    }
                    totalMemop += (s->Counters[idx] * s->MemopsPerBlock[i]);
                }

                inform << "Total memop: " << dec << totalMemop << TAB <<
                  " sampledCount " << sampledCount << ENDL;
            }
        }

        // Print application and address stream information
        RangeFile
          << "# appname       = " << stats->Application << ENDL
          << "# extension     = " << stats->Extension << ENDL
          << "# rank          = " << dec << GetTaskId() << ENDL
          << "# ntasks        = " << dec << GetNTasks() << ENDL
          << "# buffer        = " << BUFFER_CAPACITY(stats) << ENDL
          << "# total         = " << dec << totalMemop << ENDL
          << "# processed     = " << dec << sampledCount << " ("
          << ((double)sampledCount / (double)totalMemop * 100.0)
          << "% of total)" << ENDL
          << "# samplemax     = " << Sampler->AccessLimit << ENDL
          << "# sampleon      = " << Sampler->SampleOn << ENDL
          << "# sampleoff     = " << Sampler->SampleOff << ENDL
          << "# perinsn       = " << (stats->PerInstruction? "yes" : "no")
          << ENDL
          << "# lpi           = " << (stats->LoopInclusion? "yes" : "no")
          << ENDL
          << "# countimage    = " << dec << AllData->CountImages() << ENDL
          << "# countthread   = " << dec << AllData->CountThreads() << ENDL
          << "# masterthread  = " << hex << AllData->GetThreadSequence(
          pthread_self()) << ENDL
          << ENDL;

        // Print information for each image
        RangeFile << "# IMG" << TAB << "ImageHash" << TAB << "ImageSequence"
          << TAB << "ImageType" << TAB << "Name" << ENDL;

        for (set<image_key_t>::iterator iit = AllData->allimages.begin();
          iit != AllData->allimages.end(); iit++){
            AddressStreamStats* s = (AddressStreamStats*)AllData->GetData(
              (*iit), pthread_self());
            RangeFile << "IMG" << TAB << hex << (*iit) << TAB << dec
              << AllData->GetImageSequence((*iit)) << TAB
              << (s->Master ? "Executable" : "SharedLib") << TAB
              << s->Application << ENDL;
        }
        RangeFile << ENDL;


        // Print the information for each block
        RangeFile << "# " << "BLK" << TAB << "Sequence" << TAB << "Hashcode"
          << TAB << "ImageSequence" << TAB << "ThreadId" << TAB
          << "BlockCounter" << TAB << "InstructionSimulated" << TAB
          << "MinAddress" << TAB << "MaxAddress" << TAB << "AddrRange " << ENDL;
        for (set<image_key_t>::iterator iit = AllData->allimages.begin();
          iit != AllData->allimages.end(); iit++){
            for(DataManager<AddressStreamStats*>::iterator it =
              AllData->begin(*iit); it != AllData->end(*iit); ++it){

                AddressStreamStats* st = it->second;
                assert(st);
                RangeStats* aggRange;

                // Stats are collected by memid. We need to present them by
                // block. Even if perinsn, just create new RangeStats data
                // structure and compile per-memid data into it
                aggRange = new RangeStats(st->AllocCount);

                for (uint32_t memid = 0; memid < st->AllocCount; memid++){
                    uint32_t bbid;
                    RangeStats* r = (RangeStats*)st->Stats[rangeIndex];
                    if (st->PerInstruction){
                        bbid = memid;
                    } else {
                        bbid = st->BlockIds[memid];
                    }

                    aggRange->Update(bbid, r->GetMinimum(memid), 0);
                    aggRange->Update(bbid, r->GetMaximum(memid),
                      r->GetAccessCount(memid));
                }
                uint32_t MaxCapacity;
                MaxCapacity = aggRange->Capacity;

                for (uint32_t bbid = 0; bbid < MaxCapacity; bbid++){
                    // dont print blocks which weren't touched
                    if (aggRange->GetAccessCount(bbid)==0){
                        continue;
                    }
                    // this isn't necessarily true since this tool can suspend
                    // threads at any point. potentially shutting off
                    // instrumention in a block while a thread is midway through
                    // Sanity check data
                    // This assertion becomes FALSE when there are
                    // multiple addresses processed per address
                    // (e.g. with scatter/gather)
                    if (AllData->CountThreads() == 1 &&
                      !st->HasNonDeterministicMemop[bbid]){
                        if (aggRange->GetAccessCount(bbid) %
                          st->MemopsPerBlock[bbid] != 0){
                            inform << "bbid " << dec << bbid << " image " <<
                              hex << (*iit) << " accesses " << dec <<
                              aggRange->GetAccessCount(bbid) << " memops " <<
                              st->MemopsPerBlock[bbid] << ENDL;
                        }
                        assert(aggRange->GetAccessCount(bbid) %
                          st->MemopsPerBlock[bbid] == 0);
                    }

                    uint32_t idx;
                    if (st->Types[bbid] == CounterType_basicblock){
                        idx = bbid;
                    } else if (st->Types[bbid] == CounterType_instruction){
                        idx = st->Counters[bbid];
                    }

                    RangeFile  << "BLK" << TAB << dec << bbid
                      << TAB << hex << st->Hashes[bbid]
                      << TAB << dec << AllData->GetImageSequence((*iit))
                      << TAB << dec << AllData->GetThreadSequence(st->threadid)
                      << TAB << dec << st->Counters[idx]
                      << TAB << dec << aggRange->GetAccessCount(bbid)
                      << TAB << hex << aggRange->GetMinimum(bbid)
                      << TAB << hex << aggRange->GetMaximum(bbid)
                      << TAB << hex << (aggRange->GetMaximum(bbid) -
                        aggRange->GetMinimum(bbid))<<ENDL;
                } // For each block
            } // For each data manager
        } // For each image

        // Close the file
        RangeFile.close();


}

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
                
