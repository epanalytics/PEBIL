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
#include <DynamicInstrumentation.hpp>
#include <Metasim.hpp>
#include <ThreadedCommon.hpp>
#include <ScatterGatherLength.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <string.h>
#include <assert.h>

using namespace std;

void PrintSGLengthFile(DataManager<AddressStreamStats*>* AllData, 
  SamplingMethod* Sampler, int32_t sglIndex) {
    AddressStreamStats* stats = AllData->GetData(*(AllData->allimages.begin()));

    // Create the Scatter Gather Vector Length report 
    ofstream LengthFile;
    string oFile;
    const char* fileName;

    SGLengthFileName(stats,oFile);
    fileName=oFile.c_str();
    inform << "Printing scatter gather vector length results to " << 
      fileName << ENDL;
    TryOpen(LengthFile,fileName);

    uint64_t sampledCount = 0;
    uint64_t totalMemop = 0;
    // Calculate the number of access counts
    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); 
      iit != AllData->allimages.end(); iit++){
        
        for(DataManager<AddressStreamStats*>::iterator it = 
          AllData->begin(*iit); it != AllData->end(*iit); ++it) {
            thread_key_t thread = it->first;
            AddressStreamStats* s = it->second;

            VectorLengthStats* vls = (VectorLengthStats*)s->Stats[
              sglIndex];
            assert(vls);
            for (uint32_t i = 0; i < vls->Capacity; i++){
                sampledCount += vls->Counts[i];
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
    LengthFile
      << "# appname       = " << stats->Application << ENDL
      << "# extension     = " << stats->Extension << ENDL
      << "# rank          = " << dec << GetTaskId() << ENDL
      << "# ntasks        = " << dec << GetNTasks() << ENDL
      << "# buffer        = " << BUFFER_CAPACITY(stats) << ENDL
      << "# total         = " << dec << totalMemop << ENDL
      << "# processed     = " << dec << sampledCount << " (" 
      << ((double)sampledCount / (double)totalMemop * 100.0) 
      << "% of total)" << ENDL
      << "# samplemax     = " << Sampler->GetAccessLimit() << ENDL
      << "# sampleon      = " << Sampler->GetSampleOn() << ENDL
      << "# sampleoff     = " << Sampler->GetSampleOff() << ENDL
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
    LengthFile << "# IMG" << TAB << "ImageHash" << TAB << "ImageSequence"
      << TAB << "ImageType" << TAB << "Name" << ENDL;
    
    for (set<image_key_t>::iterator iit = AllData->allimages.begin();
      iit != AllData->allimages.end(); iit++){
        AddressStreamStats* s = (AddressStreamStats*)AllData->GetData(
          (*iit), pthread_self());
        LengthFile << "IMG" << TAB << hex << (*iit) << TAB << dec 
          << AllData->GetImageSequence((*iit)) << TAB 
          << (s->Master ? "Executable" : "SharedLib") << TAB 
          << s->Application << ENDL;
    }
    LengthFile << ENDL;        


    // Print the information for each block
    LengthFile << "# " << "BLK" << TAB << "Sequence" << TAB << "Hashcode" 
      << TAB << "ImageSequence" << TAB << "ThreadId" << TAB 
      << "BlockCounter" << TAB << "InstructionSimulated" << TAB 
      << "AvgVecLength" << TAB << "MinVecLength" << TAB << "MaxVecLength" 
      << ENDL;

    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); 
      iit != AllData->allimages.end(); iit++){
        for(DataManager<AddressStreamStats*>::iterator it = 
          AllData->begin(*iit); it != AllData->end(*iit); ++it){

            AddressStreamStats* st = it->second;
            assert(st);
            VectorLengthStats* aggLengths;

            // Stats are collected by memid. We need to present them by
            // block. Even if perinsn, just create new VectorLengthStats 
            // data structure and compile per-memid data into it
            aggLengths = new VectorLengthStats(st->AllocCount);

            for (uint32_t memid = 0; memid < st->AllocCount; memid++){
                uint32_t bbid;
                VectorLengthStats* vls = (VectorLengthStats*)st->Stats[
                  sglIndex];
                if (st->PerInstruction){
                    bbid = memid;
                } else {
                    bbid = st->BlockIds[memid];
                }

                aggLengths->Aggregate(bbid, vls->GetAccessCount(memid), 
                  vls->GetMinimum(memid), vls->GetMaximum(memid), 
                  vls->GetAverage(memid));
            }
            uint32_t MaxCapacity;
            MaxCapacity = aggLengths->Capacity;
            
            for (uint32_t bbid = 0; bbid < MaxCapacity; bbid++){
                // dont print blocks which weren't touched
                if (aggLengths->GetAccessCount(bbid)==0){
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
                    if (aggLengths->GetAccessCount(bbid) % 
                      st->MemopsPerBlock[bbid] != 0){
                        inform << "bbid " << dec << bbid << " image " << 
                          hex << (*iit) << " accesses " << dec << 
                          aggLengths->GetAccessCount(bbid) << " memops " << 
                          st->MemopsPerBlock[bbid] << ENDL;
                    }
                    assert(aggLengths->GetAccessCount(bbid) % 
                      st->MemopsPerBlock[bbid] == 0);                       
                }

                uint32_t idx;
                if (st->Types[bbid] == CounterType_basicblock){
                    idx = bbid;
                } else if (st->Types[bbid] == CounterType_instruction){
                    idx = st->Counters[bbid];
                }

                LengthFile  << "BLK" << TAB << dec << bbid 
                  << TAB << hex << st->Hashes[bbid]
                  << TAB << dec << AllData->GetImageSequence((*iit))
                  << TAB << dec << AllData->GetThreadSequence(st->threadid)
                  << TAB << dec << st->Counters[idx]
                  << TAB << dec << aggLengths->GetAccessCount(bbid)
                  << TAB << dec << aggLengths->GetAverage(bbid)
                  << TAB << dec << aggLengths->GetMinimum(bbid)
                  << TAB << dec << aggLengths->GetMaximum(bbid)
                  <<ENDL;                
            } // For each block
        } // For each data manager
    } // For each image

    // Close the file
    LengthFile.close();

}

void SGLengthFileName(AddressStreamStats* stats, string& oFile){
    oFile.clear();
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".");
    oFile.append("sglength");
}

VectorLengthStats::VectorLengthStats(uint32_t capacity){
    Capacity = capacity;
    Counts = new uint64_t[Capacity];
    bzero(Counts, sizeof(uint64_t) * Capacity);
    Lengths = new VectorLength*[Capacity];
    for (uint32_t i = 0; i < Capacity; i++){
        Lengths[i] = new VectorLength();
        Lengths[i]->Minimum = MAX_64BIT_VALUE;
        Lengths[i]->Maximum = 0;
        Lengths[i]->Average = 0;
    }
}

VectorLengthStats::~VectorLengthStats(){
    if (Lengths){
        delete[] Lengths;
    }
    if (Counts){
        delete[] Counts;
    }
}

bool VectorLengthStats::HasMemId(uint32_t memid){
    return (memid < Capacity);
}

double VectorLengthStats::GetAverage(uint32_t memid){
    assert(HasMemId(memid));
    return Lengths[memid]->Average;
}

uint64_t VectorLengthStats::GetMinimum(uint32_t memid){
    assert(HasMemId(memid));
    return Lengths[memid]->Minimum;
}

uint64_t VectorLengthStats::GetMaximum(uint32_t memid){
    assert(HasMemId(memid));
    return Lengths[memid]->Maximum;
}

void VectorLengthStats::Aggregate(uint32_t memid, uint64_t count, uint64_t min,
  uint64_t max, double avg){
    // If there is no count, then nothing should change
    if (count <= 0) {
        return;
    }
    VectorLength* v = (VectorLength*)(Lengths[memid]);
    if (min < v->Minimum){
        v->Minimum = min;
    }
    if (max > v->Maximum){
        v->Maximum = max;
    }

    // To update the average length we have to decide between potential overflow
    // or loss of precision. For now, let's try to prevent overflow:
    uint64_t oldCount = Counts[memid];
    double oldAverage = v->Average;
    Counts[memid] += count;
    v->Average = (oldAverage * ((double)oldCount / Counts[memid])) + 
      (avg * ((double)count / Counts[memid]));
}

void VectorLengthStats::Update(uint32_t memid, uint64_t length){
    VectorLength* v = Lengths[memid];
    if (length < v->Minimum){
        v->Minimum = length;
    }
    if (length > v->Maximum){
        v->Maximum = length;
    }

    // To update the average length without doing a muliplication and risking
    // overflow, we will update it with the following formula:
    // newAvg = oldAvg + [(length - oldAvg) / newCounts]
    // Simple Algebra will show that this is equivalent to:
    // newAvg = [(oldAvg * (newCounts - 1)) + length] / newCounts
    Counts[memid] += 1;
    double oldAverage = v->Average;
    v->Average = oldAverage + ((length - oldAverage) / Counts[memid]);
}

bool VectorLengthStats::Verify(){
    return true;
}

VectorLengthHandler::VectorLengthHandler(){
}
VectorLengthHandler::VectorLengthHandler(VectorLengthHandler& h){
    pthread_mutex_init(&mlock, NULL);
}
VectorLengthHandler::~VectorLengthHandler(){
}

void VectorLengthHandler::Print(ofstream& f){
    f << "VectorLengthHandler" << ENDL;
}

uint32_t VectorLengthHandler::Process(void* stats, BufferEntry* access){

    if(access->type == MEM_ENTRY) {
        return 0;
    } else if(access->type == VECTOR_ENTRY) {
        uint64_t length = 0;
        uint32_t memid = (uint32_t)access->memseq;
        uint16_t mask = (access->vectorAddress).mask;
        VectorLengthStats* vls = (VectorLengthStats*)stats;

        for (int i = 0; i < (access->vectorAddress).numIndices; i++) {
            if(mask % 2 == 1) {
                length++;
            }
            mask = (mask >> 1);
        }
        vls->Update(memid, length);
        return 0;
    } 
    // TODO To be implemented later
    /*} else if(access->type == PREFETCH_ENTRY) {
        uint32_t memid = (uint32_t)access->memseq;
        uint64_t addr = access->address;
        if (ExecuteSoftwarePrefetches) {
          VectorLengthStats* vls = (VectorLengthStats*)stats;
          rs->Update(memid, addr);
        }
        return 0;
   }*/
}
                
