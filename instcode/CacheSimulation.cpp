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
#include <CacheSimulation.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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

void CacheSimulationTool::AddNewHandlers(AddressStreamStats* stats) {
    for (uint32_t i = 0; i < handlers.size(); i++) {
        CacheStructureHandler* oldHandler = (CacheStructureHandler*)(
          handlers[i]);
        CacheStructureHandler* newHandler = new CacheStructureHandler(
          *oldHandler);
        stats->Handlers[indexInStats + i] = newHandler;
    }
}

void CacheSimulationTool::AddNewStreamStats(AddressStreamStats* stats) {
    for (uint32_t i = 0; i < handlers.size(); i++) {
        CacheStructureHandler* currHandler = (CacheStructureHandler*)(
          handlers[i]);
        stats->Stats[indexInStats + i] = new CacheStats(currHandler->levelCount,
          currHandler->sysId, stats->AllocCount, currHandler->hybridCache);
        CacheStats* cacheStats = (CacheStats*)stats->Stats[indexInStats + i];
        //TODO loop through stats->BlockIds and get number of blocks and pass into InitMainMemoryStats
        /* 
        std::set<uint64_t> mySet = new std::set<uint64_t>();
        for(int i=0;i<stats->AllocCount;i++){
            mySet.add(stats->BlockIds[i]);
        }
        int numOfBlocks =  mySet.size();
        assert(numOfBlocks == stats->BlockCount);
        */
        cacheStats->InitMainMemoryStats(currHandler, stats->BlockCount);
    }
}

uint32_t CacheSimulationTool::CreateHandlers(uint32_t index, StringParser* 
  parser){
    string cachedf;
    const char* cs = HandleEnvVariables(index, parser, cachedf);

    ifstream CacheFile(cs);
    uint32_t retSize = ReadCacheDescription(CacheFile, parser, cachedf);

    return retSize;
}


void CacheSimulationTool::FinalizeTool(DataManager<AddressStreamStats*>* 
  AllData, SamplingMethod* Sampler) {
    AddressStreamStats* stats = AllData->GetData(pthread_self());
    uint32_t numCaches = handlers.size();

    // Create the Cache Simulation Report
    ofstream MemFile;
    string oFile;
    const char* fileName;

    // dump cache simulation results
    CacheSimulationFileName(stats, oFile);
    fileName = oFile.c_str();
    inform << "Printing cache simulation results to " << fileName << ENDL;
    TryOpen(MemFile, fileName);

    // Create the MainMemoryLogging Report
    ofstream LogFile;
    string lFile;
    const char* logName;

    if(LoadStoreLogging){
        // dump MainMemoryLogging results
        LogFileName(stats, lFile);
        logName = lFile.c_str();
        inform << "Printing Memory Logging results to " << logName << ENDL;
        TryOpen(LogFile, logName);
    }

    uint64_t sampledCount = 0;
    uint64_t totalMemop = 0;
    // Calculate the number of access counts
    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); 
      iit != AllData->allimages.end(); iit++){

        for(DataManager<AddressStreamStats*>::iterator it = 
          AllData->begin(*iit); it != AllData->end(*iit); ++it) {
            thread_key_t thread = it->first;
            AddressStreamStats* s = it->second;

            CacheStats* c = (CacheStats*)(s->Stats[indexInStats]);
            assert(c);
            for (uint32_t i = 0; i < c->Capacity; i++){
                sampledCount += c->GetAccessCount(i);
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
                } else { 
                    assert(0 && "Improper Type");
                }
                totalMemop += (s->Counters[idx] * s->MemopsPerBlock[i]);
            }

            inform << "Total memop: " << dec << totalMemop << TAB << 
              " sampledCount " << sampledCount<< ENDL;
        }
    }

    PrintApplicationHeader(MemFile, AllData, Sampler, totalMemop, sampledCount);
    if(LoadStoreLogging){
        PrintApplicationHeader(LogFile, AllData, Sampler, totalMemop, sampledCount);
    }
        
    // Print statisics for each cache structure 
    for (uint32_t sys = indexInStats; sys < indexInStats + numCaches; sys++) {
        for (set<image_key_t>::iterator iit = AllData->allimages.begin(); 
          iit != AllData->allimages.end(); iit++) {

            bool first = true;

            for(DataManager<AddressStreamStats*>::iterator it = 
              AllData->begin(*iit); it != AllData->end(*iit); ++it) {
                AddressStreamStats* s = it->second;
                thread_key_t thread = it->first;
                assert(s);

                CacheStats* c = (CacheStats*)s->Stats[sys];
                assert(c->Capacity == s->AllocCount);

                // Sanity check the cache structure
                if(!c->Verify()) {
                    warn << "Cache structure failed verification for "
                      "system " << c->SysId << ", image " << hex << *iit 
                      << ", thread " << hex << thread << ENDL;
                }

                if (first){
                    PrintSysidInfo(MemFile, c, iit);
                    if(LoadStoreLogging){
                        PrintSysidInfo(LogFile, c, iit);
                    }
                    first = false;
                }

                PrintThreadidInfo(MemFile, thread, AllData);
                if(LoadStoreLogging){
                    PrintThreadidInfo(LogFile, thread, AllData);
                }

                // Print stats for each level in the cache structure
                for (uint32_t lvl = 0; lvl < c->LevelCount; lvl++){
                    uint64_t h = c->GetHits(lvl);
                    uint64_t m = c->GetMisses(lvl);
                    uint64_t t = h + m;
                    MemFile << "l" << dec << lvl << "[" << h << "/" << t 
                      << "(" << CacheStats::GetHitRate(h, m) << ")] ";
                }

                if(LoadStoreLogging){
                    MemFile<<"\n# Load store stats ";
                    LogFile<<"Load store stats ";
                    for (uint32_t lvl = 0; lvl < c->LevelCount; lvl++){
                        uint64_t l = c->GetLoads(lvl);
                        uint64_t s = c->GetStores(lvl);
                        uint64_t t = l + s;
                        double ratio=0.0f;
                        if(t!=0)
                          ratio= (double) l/t;
                        MemFile << " l" << dec << lvl << "[" << l << "/" 
                          << t << "(" << (ratio)<<")] ";
                        LogFile << " l" << dec << lvl << "[" << l << "/" 
                          << t << "(" << (ratio)<<")] ";
                    }                                   
                    LogFile << ENDL << "#" << TAB;
                    LogFile << "SetCount: " << dec << c->mainMemoryStats[0]->numOfSets
                      << TAB << "LineCount: " << dec << c->mainMemoryStats[0]->numOfLinesInSet;
                }

                if(c->hybridCache) {
                    uint64_t h=c->GetHybridHits();
                    uint64_t m=c->GetHybridMisses();
                    uint64_t t_hm= h+m; 
                    double ratio_hm,ratio_ls;
                     if(t_hm!=0)
                        ratio_hm= (double) h/t_hm;
                    MemFile << ENDL ;     
                    MemFile <<"#Hybrid cache stats\tHits " << "[" << h << 
                      "/" << t_hm << "(" << (ratio_hm)<< ")]";

                    if(LoadStoreLogging){
                        uint64_t l=c->GetHybridLoads();
                        uint64_t s=c->GetHybridStores();
                        uint64_t t_ls= l+s; 
                        if(t_ls!=0)
                            ratio_ls=(double) l/t_ls;                                                                
                        MemFile<<" ; Loads " << "[" << l << "/" << t_ls 
                          << "(" << (ratio_ls)<< ")]";
                    }
                } // if hybrid cache                               
                 
                MemFile << ENDL;
                if(LoadStoreLogging){
                    LogFile << ENDL;
                }
            } // for each data manager
        } // for each image
        MemFile << ENDL;
        if(LoadStoreLogging){
            LogFile << ENDL;
        }
    } // for each cache structure

    // Create array to keep track of hybrid caches
    uint32_t* HybridCacheStatus = (uint32_t*)malloc(numCaches * 
      sizeof(uint32_t) );
    for (uint32_t sys = 0; sys < numCaches; sys++) {
        CacheStructureHandler* CheckHybridStructure = 
          (CacheStructureHandler*)stats->Handlers[sys + indexInStats];
        HybridCacheStatus[sys] = CheckHybridStructure->hybridCache;
    }

    PrintPerBlockCacheSimData(MemFile, AllData);

    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); 
      iit != AllData->allimages.end(); iit++) {
        for(DataManager<AddressStreamStats*>::iterator it = 
          AllData->begin(*iit); it != AllData->end(*iit); ++it) {

            AddressStreamStats* st = it->second;
            assert(st);
            CacheStats** aggstats;

            // compile per-instruction stats into blocks
            aggstats = new CacheStats*[numCaches];
            for (uint32_t sys = 0; sys < numCaches; sys++) {

                CacheStats* s = (CacheStats*)st->Stats[sys + indexInStats];
                assert(s);
                s->Verify();

                CacheStats* c = new CacheStats(s->LevelCount, s->SysId,
                  st->BlockCount, s->hybridCache);

                //MainMemory* refMem = s->mainMemoryStats[0];
                c->mainMemoryStats = new MainMemory*[st->BlockCount];
                for (int i=0;i<st->BlockCount;i++){
                    c->mainMemoryStats[i] = s->mainMemoryStats[i];
                }

                aggstats[sys] = c;

                for (uint32_t memid = 0; memid < st->AllocCount; 
                        memid++){

                    uint32_t bbid;
                    if (st->PerInstruction){
                        bbid = memid;
                    } else {
                        bbid = st->BlockIds[memid];
                    }

                    for (uint32_t lvl = 0; lvl < c->LevelCount; lvl++) {

                        c->Hit(bbid, lvl, s->GetHits(memid, lvl));
                        c->Miss(bbid, lvl, s->GetMisses(memid, lvl));

                        if(LoadStoreLogging){
                            c->Load(bbid, lvl, s->GetLoads(memid, lvl));
                            c->Store(bbid, lvl, s->GetStores(memid, lvl));
                        }
                    } // for each cache level

                    if(LoadStoreLogging){ //not used anymore
                        /*if( c->mainMemoryStats[0]->numOfLinesInSet > 1) {
                            for(int i=0;i<c->mainMemoryStats[0]->numOfSets;i++){
                                for(int j=0;j<c->mainMemoryStats[0]->numOfLinesInSet;j++){
                                    NestedHash* CreadInsMap = c->mainMemoryStats[bbid]->readInsMap; 
                                    NestedHash* CwriteOutsMap = c->mainMemoryStats[bbid]->writeOutsMap;
                                    NestedHash* SreadInsMap = s->mainMemoryStats[memid]->readInsMap; 
                                    NestedHash* SwriteOutsMap = s->mainMemoryStats[memid]->writeOutsMap;
                                    
                                    //c->mainMemoryStats[bbid]->readInsMap[i] += s->mainMemoryStats[memid]->readInsMap[i];
                                    //c->mainMemoryStats[bbid]->writeOutsMap[i] += s->mainMemoryStats[memid]->writeOutsMap[i];
                                    uint32_t toAddRead = SreadInsMap->get(i,j);
                                    uint32_t toAddWrite = SwriteOutsMap->get(i,j);
                                    if (toAddRead > 0){
                                        CreadInsMap->put(i,j,toAddRead);
                                    }
                                    if (toAddWrite > 0){
                                        CwriteOutsMap->put(i,j,toAddWrite);
                                    }
                                }
                            }
                        } else {
                            for(int i=0;i<c->mainMemoryStats[0]->numOfSets;i++){
                                EasyHash* CdirInsMap = c->mainMemoryStats[bbid]->dirInsMap;
                                EasyHash* CdirOutsMap = c->mainMemoryStats[bbid]->dirOutsMap;
                                EasyHash* SdirInsMap = s->mainMemoryStats[bbid]->dirInsMap;
                                EasyHash* SdirOutsMap = s->mainMemoryStats[bbid]->dirOutsMap;

                                uint32_t toAddRead = SdirInsMap->get(i);
                                uint32_t toAddWrite = SdirOutsMap->get(i);
                                if (toAddRead > 0) {
                                    CdirInsMap->add(i, toAddRead);
                                }
                                if (toAddWrite > 0) {
                                    CdirOutsMap->add(i, toAddWrite);
                                }
                            }
                        }*/
                    }
                } // for each memop 

                if(!c->Verify()) {
                    warn << "Failed check on aggregated cache stats" 
                      << ENDL;
                }

                if(c->hybridCache){
                    for (uint32_t memid = 0; memid < st->AllocCount; 
                            memid++){
                        uint32_t bbid;
                        if (st->PerInstruction){
                            bbid = memid;
                        } else {
                            bbid = st->BlockIds[memid];
                        }          

                        c->HybridHit(bbid,s->GetHybridHits(memid)) ;
                        c->HybridMiss(bbid,s->GetHybridMisses(memid));  

                        if(LoadStoreLogging){
                            c->HybridLoad(bbid,s->GetHybridLoads(memid)); 
                            c->HybridStore(bbid,s->GetHybridStores(memid));
                        }
                    } // for each memop                                    
                } // if a hybrid cache         
            //delete s here
            delete s;
            } // for each cache structure

            CacheStats* root = aggstats[0];
            uint32_t MaxCapacity = root->Capacity;

            if(LoadStoreLogging) {
                LogFile << "#" << TAB << "BLK" << TAB << "BLKID" << TAB << "BLK HASH"
                  << TAB << "ImageSequence" << TAB << "ThreadSequence" 
                  TAB << "SYSID1:MISSES" << TAB << "SYSID2:MISSES ..." << ENDL;
                LogFile << "#" << TAB << "BLK" << TAB << "SYSID" << TAB << "SET"
                  << TAB << "LINE" << TAB << "READS" << TAB << "WRITES" << ENDL << ENDL;
            }

            // Print the data for each block 
            for (uint32_t bbid = 0; bbid < MaxCapacity; bbid++) {
                // dont print blocks which weren't touched
                if (root->GetAccessCount(bbid) == 0) {
                    continue;
                }
                // this isn't necessarily true since this tool can suspend 
                // threads at any point. potentially shutting off 
                // instrumention in a block while a thread is midway through
                // Sanity check data
                // This assertion becomes FALSE when there are
                // multiple addresses processed per address 
                // (e.g. with scatter/gather)
                if ((AllData->CountThreads() == 1) && 
                  !st->HasNonDeterministicMemop[bbid]){
                    if ((root->GetAccessCount(bbid) % 
                      st->MemopsPerBlock[bbid]) != 0){
                        inform << "bbid " << dec << bbid << " image " << 
                          hex << (*iit) << " accesses " << dec << 
                          root->GetAccessCount(bbid) << " memops " << 
                          st->MemopsPerBlock[bbid] << ENDL;
                    }
                    assert(root->GetAccessCount(bbid) % 
                      st->MemopsPerBlock[bbid] == 0);
                }

                uint32_t idx;
                if (st->Types[bbid] == CounterType_basicblock){
                    idx = bbid;
                } else if (st->Types[bbid] == CounterType_instruction){
                    idx = st->Counters[bbid];
                }

                MemFile << "BLK" << TAB << dec << bbid
                  << TAB << hex << st->Hashes[bbid]
                  << TAB << dec << AllData->GetImageSequence((*iit))
                  << TAB << dec << AllData->GetThreadSequence(st->threadid)
                  << ENDL;

                if(LoadStoreLogging){
                    LogFile << "BLK" << TAB << dec << bbid
                      << TAB << hex << st->Hashes[bbid]
                      << TAB << dec << AllData->GetImageSequence((*iit))
                      << TAB << dec << AllData->GetThreadSequence(st->threadid);
                    for (uint32_t sys = 0; sys < numCaches; sys++){
                        CacheStats* c = aggstats[sys];
                        //NOTE threading issue here in future perhapps
                        uint32_t lastLevel = c->LevelCount - 1;
                        LogFile << TAB << dec << c->SysId << ":" 
                          << c->GetMisses(bbid, lastLevel);
                    }
                    LogFile << ENDL;

                    for (uint32_t sys = 0; sys < numCaches; sys++){
                        CacheStats* c = aggstats[sys];
                        //NOTE threading issue here in future perhapps
                        uint32_t lastLevel = c->LevelCount - 1;
                        LogFile << "# " << dec << c->SysId << ":" 
                          << c->GetMisses(bbid, lastLevel) << ENDL;
                    }
                }

                for (uint32_t sys = 0; sys < numCaches; sys++){
                    CacheStats* c = aggstats[sys];

                    if (AllData->CountThreads() == 1){
                        assert(root->GetAccessCount(bbid) == 
                          c->GetHits(bbid, 0) + c->GetMisses(bbid, 0));
                    }

                    for (uint32_t lvl = 0; lvl < c->LevelCount; lvl++){
                        if(LoadStoreLogging){
                            MemFile << TAB << dec << c->SysId;
                            MemFile << TAB << dec << (lvl+1);
                            MemFile << TAB << dec << c->GetHits(bbid, lvl)
                              << TAB << dec << c->GetMisses(bbid, lvl)
                              << TAB << dec << c->GetLoads(bbid,lvl)
                              << TAB << dec << c->GetStores(bbid,lvl)
                              << ENDL;  
                        } else {
                            MemFile << TAB << dec << c->SysId
                              << TAB << dec << (lvl+1)
                              << TAB << dec << c->GetHits(bbid, lvl)
                              << TAB << dec << c->GetMisses(bbid, lvl)
                              << ENDL;
                        }
                    }
                    if (LoadStoreLogging) {
                        MemFile << TAB << dec << c->SysId;
                        MemFile << TAB << "M"
                          << TAB << dec << c->GetMisses(bbid, c->LevelCount-1)
                          << TAB << dec << 0
                          << TAB << dec << c->mainMemoryStats[bbid]->GetLoads()
                          << TAB << dec << c->mainMemoryStats[bbid]->GetStores()
                          << ENDL; 

                        uint32_t numOfSets = c->mainMemoryStats[bbid]->numOfSets;
                        uint32_t numOfLines = c->mainMemoryStats[bbid]->numOfLinesInSet;
                        NestedHash* readWritesMap;
                        EasyHash* inOutsMap;
                        if (numOfLines > 1) {
                            readWritesMap = c->mainMemoryStats[bbid]->readWritesMap;
                        } else {
                            inOutsMap = c->mainMemoryStats[bbid]->inOutsMap;
                        }

                        if (numOfLines > 1) {
                            for(int i=0;i<numOfSets;i++){
                                for(int j=0;j<numOfLines;j++){
                                    bool readWrite = readWritesMap->contains(i,j);
                                    if( readWrite) {
                                        LogFile << TAB << bbid << TAB << dec << c->SysId
                                          << TAB << dec << i
                                          << TAB << dec << j;
                                        uint32_t* tempP;
                                        uint32_t tempA[2] = {0, 0};
                                        tempP = (uint32_t*)tempA;
                                        tempP = readWritesMap->get(i,j,tempP);
                                        LogFile << TAB << dec << tempP[0];
                                        LogFile << TAB << dec << tempP[1];
                                        LogFile << ENDL;
                                    }
                                }
                            }
                        }
                        else {
                            for(int i=0;i<numOfSets;i++){
                                bool readWrite = inOutsMap->contains(i);   
                                if( readWrite) {
                                    LogFile << TAB << bbid << TAB << dec << c->SysId
                                      << TAB << dec << i
                                      << TAB << "0";
                                    uint32_t* tempP;
                                    uint32_t tempA[2] = {0, 0};
                                    tempP = (uint32_t*)tempA;
                                    tempP = inOutsMap->get(i, tempP);
                                    LogFile << TAB << dec << tempP[0];
                                    LogFile << TAB << dec << tempP[1]; 
                                    LogFile << ENDL;
                                }
                            }
                        }
                    }

                    if(HybridCacheStatus[sys]){
                        MemFile << TAB << dec << c->SysId
                          << TAB << dec << (c->LevelCount)
                          << TAB << dec << c->GetHybridHits(bbid)
                          << TAB << dec << c->GetHybridMisses(bbid)
                          << TAB << dec << c->GetHybridLoads(bbid)
                          << TAB << dec << c->GetHybridStores(bbid)
                          << ENDL;
                    } // if a hybrid cache
                } // for each cache structure
            } // for each block

            // Delete aggregated stats
            for (uint32_t i = 0; i < numCaches; i++){
                delete aggstats[i];
            }
            delete[] aggstats;

        } // for each data manager
    } // for each image

    // Close the files   
    MemFile.close();
    LogFile.close();
}

void CacheSimulationTool::PrintApplicationHeader(ofstream& file, 
  DataManager<AddressStreamStats*>* AllData, SamplingMethod* Sampler, 
  uint64_t totalMemop, uint64_t sampledCount){

    AddressStreamStats* stats = AllData->GetData(pthread_self());
    uint32_t numCaches = handlers.size();
    // Print the application and address stream information
    file << "# appname       = " << stats->Application << ENDL
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
      << "# numcache      = " << numCaches << ENDL
      << "# perinsn       = " << (stats->PerInstruction? "yes" : "no") 
      << ENDL 
      << "# lpi           = " << (stats->LoopInclusion? "yes" : "no")  
      << ENDL
      << "# countimage    = " << dec << AllData->CountImages() << ENDL
      << "# countthread   = " << dec << AllData->CountThreads() << ENDL
      << "# masterthread  = " << hex << AllData->GetThreadSequence(
      pthread_self()) << ENDL 
      << "# LoadStoreLogging = " << dec << LoadStoreLogging << ENDL
      << ENDL;

    // Print information for each image
    file << "# IMG" << TAB << "ImageHash" << TAB << "ImageSequence"
      << TAB << "ImageType" << TAB << "Name" << ENDL;

    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); 
      iit != AllData->allimages.end(); iit++){
        AddressStreamStats* s = (AddressStreamStats*)AllData->GetData(
          (*iit), pthread_self());
        file << "IMG" << TAB << hex << (*iit) 
          << TAB << dec << AllData->GetImageSequence((*iit))
          << TAB << (s->Master ? "Executable" : "SharedLib") 
          // FIXME master is not necessarily the executable
          << TAB << s->Application << ENDL;
    }
    file << ENDL;
}

void CacheSimulationTool::PrintSysidInfo(ofstream& file, 
  CacheStats* c, set<image_key_t>::iterator iit){
    file << "# sysid" << dec << c->SysId << " in image "
      << hex << (*iit) << ENDL;
}

void CacheSimulationTool::PrintThreadidInfo(ofstream& file, thread_key_t thread, 
  DataManager<AddressStreamStats*>* AllData){

    file << "# Threadid: " << dec << AllData->GetThreadSequence(
      thread) << TAB;
}

void CacheSimulationTool::PrintPerBlockCacheSimData(ofstream& MemFile, 
  DataManager<AddressStreamStats*>* AllData){

    // Finally, going to print per-block cache simulation data. 
    // First, the header
    MemFile << "# " << "BLK" << TAB << "Sequence" << TAB << "Hashcode" 
      << TAB << "ImageSequence" << TAB << "ThreadId " << ENDL;        
    if(LoadStoreLogging) {
        MemFile << "# " << TAB << "SysId" << TAB << "Level" << TAB 
          << "HitCount" << TAB << "MissCount" << TAB << "LoadCount" << TAB 
          << "StoreCount" << ENDL;
    } else {
        MemFile<< "# " << TAB << "SysId" << TAB << "Level" << TAB << 
          "HitCount" << TAB << "MissCount" << ENDL;   
    }
};

void CacheSimulationTool::CacheSimulationFileName(AddressStreamStats* stats, 
  string& oFile){
    oFile.clear();
    const char* prefix = getenv(ENV_OUTPUT_PREFIX);
    if(prefix != NULL) {
        oFile.append(prefix);
        oFile.append("/");
    }
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".");
    oFile.append("cachesim");
}

void CacheSimulationTool::LogFileName(AddressStreamStats* stats, string& oFile){
    oFile.clear();
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".");
    oFile.append("memlog");
}

string CacheSimulationTool::GetCacheDescriptionFile(StringParser* parser){
    char* e = parser->GetEnv("METASIM_CACHE_DESCRIPTIONS");
    string knobvalue;

    if (e != NULL){
        knobvalue = (string)e;
    }

    if (e == NULL || knobvalue.compare(0, 1, "$") == 0){
        string str;
        const char* freeenv = getenv(METASIM_ENV);
        if (freeenv == NULL){
            ErrorExit("default cache descriptions file requires that " 
                    METASIM_ENV " be set", MetasimError_Env);
        }

        str.append(freeenv);
        str.append("/" DEFAULT_CACHE_FILE);

        return str;
    }
    return knobvalue;
}

const char* CacheSimulationTool::HandleEnvVariables(uint32_t index, 
        StringParser* parser, string& cachedf){
    indexInStats = index;

    // Can tinker with this at runtime using the environment variable
    // METASIM_LIMIT_HIGH_ASSOC if desired.
    uint32_t SaveHashMin = MinimumHighAssociativity;
    bool flag = (parser->ReadEnvUint32("METASIM_LIMIT_HIGH_ASSOC", 
      &MinimumHighAssociativity));
    if (!flag){
        MinimumHighAssociativity = SaveHashMin;
    }

    if(!(parser->ReadEnvUint32("METASIM_LOAD_LOG",&LoadStoreLogging))){
        LoadStoreLogging = 0;
    }
    if(!(parser->ReadEnvUint32("METASIM_DIRTY_CACHE",&DirtyCacheHandling))){
        DirtyCacheHandling = 0;
    }

    if(DirtyCacheHandling){
        if(!LoadStoreLogging){
            ErrorExit(" DirtyCacheHandling is enabled without LoadStoreLogging "
              ,MetasimError_FileOp);
        }
    }

    inform << " LoadStoreLogging " << LoadStoreLogging << " DirtyCacheHandling "
      << DirtyCacheHandling << ENDL;

    // read caches to simulate
    cachedf = GetCacheDescriptionFile(parser);
    return cachedf.c_str();
}

uint32_t CacheSimulationTool::ReadCacheDescription(istream& stream, 
  StringParser* parser, string& cachedf){
    bool streamResult = stream.fail();
    if (streamResult){
        ErrorExit("cannot open cache descriptions file: " << cachedf, 
          MetasimError_FileOp);
    }

    string line;
    while (getline(stream, line)){
        if (parser->IsEmptyComment(line)){
            continue;
        }
        CacheStructureHandler* c = new CacheStructureHandler();
        if (!c->Init(line, MinimumHighAssociativity, LoadStoreLogging, DirtyCacheHandling)){
            ErrorExit("cannot parse cache description line: " << line, 
              MetasimError_StringParse);
        }
        assert(!(c->hybridCache) && "Hybrid cache deprecated");
        handlers.push_back(c);
    }
    uint32_t CountCacheStructures = handlers.size();
    assert(CountCacheStructures > 0 && "No cache structures found for "
            "simulation");
    return handlers.size();
}

CacheStats::CacheStats(uint32_t lvl, uint32_t sysid, uint32_t capacity, 
  uint32_t hybridcache){
    LevelCount = lvl;
    SysId = sysid;
    Capacity = capacity;
    hybridCache=hybridcache;
    mainMemoryStats = new MainMemory*[Capacity];
    //TODO this has to be changed Capcity-> num of basic blocks

    Stats = new LevelStats*[Capacity];
    if(hybridCache){   
        HybridMemStats=new LevelStats[Capacity];
        for (uint32_t i = 0; i < Capacity; i++){
            memset(&HybridMemStats[i],0,sizeof(LevelStats));
        }       
    }

    for (uint32_t i = 0; i < Capacity; i++){
        NewMem(i);
    }
    assert(Verify());
}

CacheStats::~CacheStats(){
    if (Stats){
        for (uint32_t i = 0; i < Capacity; i++){
            if (Stats[i]){
                delete[] Stats[i];
            }
            /*if (mainMemoryStats[i]){
                delete mainMemoryStats[i];
            }*/
        }
        delete[] Stats;
        //delete[] mainMemoryStats;
    }
}

void CacheStats::InitMainMemoryStats(CacheStructureHandler* handler, uint32_t BlockCount ){
    uint32_t lastLevel = handler->levelCount-1;
    uint32_t numOfSets = handler->levels[lastLevel]->GetSetCount();
    uint32_t numOfLinesInSet = handler->levels[lastLevel]->GetAssociativity();
    uint32_t sizeOfLine = handler->levels[lastLevel]->GetLineSize();
    /*for(int i=0;i<Capacity;i++){
        mainMemoryStats[i] = new MainMemory(numOfSets, numOfLinesInSet, sizeOfLine);
        assert(mainMemoryStats[i]->GetLoads()==0);
    }*/
    for(int i=0;i<BlockCount;i++){
        mainMemoryStats[i] = new MainMemory(numOfSets, numOfLinesInSet, sizeOfLine);
        assert(mainMemoryStats[i]->GetLoads()==0);
    }
}

float CacheStats::GetHitRate(LevelStats* stats){
    return GetHitRate(stats->hitCount, stats->missCount);
}

float CacheStats::GetHitRate(uint64_t hits, uint64_t misses){
    if (hits + misses == 0){
        return 0.0;
    }
    return ((float)hits) / ((float)hits + (float)misses);
}

void CacheStats::ExtendCapacity(uint32_t newSize){
    assert(0 && "Should not be updating the size of this dynamically");
    LevelStats** nn = new LevelStats*[newSize];

    memset(nn, 0, sizeof(LevelStats*) * newSize);
    memcpy(nn, Stats, sizeof(LevelStats*) * Capacity);

    delete[] Stats;
    Stats = nn;
}

void CacheStats::NewMem(uint32_t memid){
    assert(memid < Capacity);

    LevelStats* mem = new LevelStats[LevelCount];
    memset(mem, 0, sizeof(LevelStats) * LevelCount);
    Stats[memid] = mem;
}

void CacheStats::Load(uint32_t memid, uint32_t lvl){
    Load(memid, lvl, 1);
}

void CacheStats::Load(uint32_t memid, uint32_t lvl, uint32_t cnt){
    Stats[memid][lvl].loadCount += cnt;
}

void CacheStats::HybridLoad(uint32_t memid){
    HybridLoad(memid, 1);
}

void CacheStats::HybridLoad(uint32_t memid, uint32_t cnt){
    HybridMemStats[memid].loadCount += cnt;
}


void CacheStats::Store(uint32_t memid, uint32_t lvl){
    Store(memid, lvl, 1);
}

void CacheStats::Store(uint32_t memid, uint32_t lvl, uint32_t cnt){
    Stats[memid][lvl].storeCount += cnt;
}

void CacheStats::HybridStore(uint32_t memid){
    HybridStore(memid, 1);
}

void CacheStats::HybridStore(uint32_t memid, uint32_t cnt){
    HybridMemStats[memid].storeCount += cnt;
}


uint64_t CacheStats::GetLoads(uint32_t memid, uint32_t lvl){
    return Stats[memid][lvl].loadCount;
}

uint64_t CacheStats::GetLoads(uint32_t lvl){
    uint64_t loads = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        loads += Stats[i][lvl].loadCount;
    }
    return loads;
}

uint64_t CacheStats::GetHybridLoads(uint32_t memid){
    return HybridMemStats[memid].loadCount;
}


uint64_t CacheStats::GetHybridLoads(){
    uint64_t loads = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        loads += HybridMemStats[i].loadCount;
    }
    return loads;
}


uint64_t CacheStats::GetStores(uint32_t memid, uint32_t lvl){
    return Stats[memid][lvl].storeCount;
}

uint64_t CacheStats::GetStores(uint32_t lvl){
    uint64_t stores = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        stores += Stats[i][lvl].storeCount;
    }
    return stores;
}

uint64_t CacheStats::GetHybridStores(uint32_t memid){
    return HybridMemStats[memid].storeCount;
}

uint64_t CacheStats::GetHybridStores(){
    uint64_t stores = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        stores += HybridMemStats[i].storeCount;
    }
    return stores;
}

void CacheStats::Hit(uint32_t memid, uint32_t lvl){
    Hit(memid, lvl, 1);
}

void CacheStats::Miss(uint32_t memid, uint32_t lvl){
    Miss(memid, lvl, 1);
}

void CacheStats::Miss(uint32_t memid, uint32_t lvl, uint32_t cnt){
    Stats[memid][lvl].missCount += cnt;
}

void CacheStats::HybridHit(uint32_t memid){
    HybridHit(memid, 1);
}

void CacheStats::HybridHit(uint32_t memid, uint32_t cnt){
    HybridMemStats[memid].hitCount += cnt;
}

void CacheStats::HybridMiss(uint32_t memid){
    HybridMiss(memid, 1);
}

void CacheStats::HybridMiss(uint32_t memid, uint32_t cnt){
    HybridMemStats[memid].missCount += cnt;
}

void CacheStats::Hit(uint32_t memid, uint32_t lvl, uint32_t cnt){
    Stats[memid][lvl].hitCount += cnt;
}


uint64_t CacheStats::GetHits(uint32_t memid, uint32_t lvl){
    return Stats[memid][lvl].hitCount;
}

uint64_t CacheStats::GetHits(uint32_t lvl){
    uint64_t hits = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        hits += Stats[i][lvl].hitCount;
    }
    return hits;
}

uint64_t CacheStats::GetMisses(uint32_t memid, uint32_t lvl){
    return Stats[memid][lvl].missCount;
}

uint64_t CacheStats::GetMisses(uint32_t lvl){
    uint64_t hits = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        hits += Stats[i][lvl].missCount;
    }
    return hits;
}

uint64_t CacheStats::GetHybridHits(uint32_t memid){
    return HybridMemStats[memid].hitCount;
}

uint64_t CacheStats::GetHybridHits(){
    uint64_t hits = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        hits += HybridMemStats[i].hitCount;
    }
    return hits;
}

uint64_t CacheStats::GetHybridMisses(uint32_t memid){
    return HybridMemStats[memid].missCount;
}

uint64_t CacheStats::GetHybridMisses(){
    uint64_t misses = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        misses += HybridMemStats[i].missCount;
    }
    return misses;
}

bool CacheStats::HasMemId(uint32_t memid){
    if (memid >= Capacity){
        return false;
    }
    if (Stats[memid] == NULL){
        return false;
    }
    return true;
}

LevelStats* CacheStats::GetLevelStats(uint32_t memid, uint32_t lvl){
    return &(Stats[memid][lvl]);
}

uint64_t CacheStats::GetAccessCount(uint32_t memid){
    LevelStats* l1 = GetLevelStats(memid, 0);
    if (l1){
        return (l1->hitCount + l1->missCount);
    }
    return 0;
}

float CacheStats::GetHitRate(uint32_t memid, uint32_t lvl){
    return GetHitRate(GetLevelStats(memid, lvl));
}

float CacheStats::GetCumulativeHitRate(uint32_t memid, uint32_t lvl){
    uint64_t tcount = GetAccessCount(memid);
    if (tcount == 0){
        return 0.0;
    }

    uint64_t hits = 0;
    for (uint32_t i = 0; i < lvl; i++){
        hits += GetLevelStats(memid, i)->hitCount;
    }
    return ((float)hits / (float)GetAccessCount(memid));
}

bool CacheStats::Verify(){
    for(uint32_t memid = 0; memid < Capacity; ++memid){

        uint64_t prevMisses = Stats[memid][0].missCount;

        for(uint32_t level = 1; level < LevelCount; ++level){
            uint64_t hits = Stats[memid][level].hitCount;
            uint64_t misses = Stats[memid][level].missCount;
            if(hits + misses != prevMisses){
                warn << "Inconsistent hits/misses for memid " << memid << 
                  " level " << level << " " << hits << " + " << misses << 
                  " != " << prevMisses << ENDL;
                return false;
            }
            prevMisses = misses;
        }
    }
    return true;
}

CacheLevel::CacheLevel(){
}

void CacheLevel::Init(CacheLevel_Init_Interface){
    level = lvl;
    size = sizeInBytes;
    associativity = assoc;
    linesize = lineSz;
    replpolicy = pol;
    loadStoreLogging = loadStore;
    dirtyCacheHandling = dirtyCache;
    toEvict=false;
    toEvictAddresses=new vector<uint64_t>;

    countsets = size / (linesize * associativity);

    linesizeBits = 0;
    while (lineSz > 0){
        linesizeBits++;
        lineSz = (lineSz >> 1);
    }
    linesizeBits--;
    contents = new uint64_t*[countsets];
    dirtystatus= new bool*[countsets];
    for (uint32_t i = 0; i < countsets; i++){
        contents[i] = new uint64_t[associativity];
        memset(contents[i], 0, sizeof(uint64_t) * associativity);

        dirtystatus[i]=new bool[associativity];
        memset(dirtystatus[i],0, sizeof(bool) * associativity );   
        // initialized to false i.e. cacheline is not dirty.
    }

    recentlyUsed = NULL;
    historyUsed = NULL;
    if (replpolicy == ReplacementPolicy_nmru){
        recentlyUsed = new uint32_t[countsets];
        memset(recentlyUsed, 0, sizeof(uint32_t) * countsets);
    }
    else if (replpolicy == ReplacementPolicy_trulru){
        recentlyUsed = new uint32_t[countsets];
        memset(recentlyUsed, 0, sizeof(uint32_t) * countsets);
        historyUsed = new history*[countsets];
        for(int s = 0; s < countsets; ++s) {
            historyUsed[s] = new history[assoc];
            historyUsed[s][0].prev = assoc-1;
            historyUsed[s][0].next = 1;
            for(int a = 1; a < assoc; ++a) {
                historyUsed[s][a].prev = a-1;
                historyUsed[s][a].next = (a+1)%assoc;
            }
        }
    }
}

void HighlyAssociativeCacheLevel::Init(CacheLevel_Init_Interface){
    fastcontents = new pebil_map_type<uint64_t, uint32_t>*[countsets];
    fastcontentsdirty = new pebil_map_type<uint64_t, bool>*[countsets];
    for (uint32_t i = 0; i < countsets; i++){
        fastcontents[i] = new pebil_map_type<uint64_t, uint32_t>();
        fastcontents[i]->clear();

        fastcontentsdirty[i] = new pebil_map_type<uint64_t, bool>();
        fastcontentsdirty[i]->clear(); 
        // initialized to false i.e. cacheline is not dirty.
    }

}

HighlyAssociativeCacheLevel::~HighlyAssociativeCacheLevel(){
    if (fastcontents){
        for (uint32_t i = 0; i < countsets; i++){
            if (fastcontents[i]){
                delete fastcontents[i];
            }
        }
        delete[] fastcontents;
    }
    if (fastcontentsdirty){
        for (uint32_t i = 0; i < countsets; i++){
            if (fastcontentsdirty[i]){
                delete fastcontentsdirty[i];
            }
        }
        delete[] fastcontentsdirty;
    }    
}

CacheLevel::~CacheLevel(){
    if (contents){
        for (uint32_t i = 0; i < countsets; i++){
            if (contents[i]){
                delete[] contents[i];
            }
        }
        delete[] contents;
    }
    if (recentlyUsed){
        delete[] recentlyUsed;
    }
    if (historyUsed){
        for(int s = 0; s < countsets; ++s){
            delete[] historyUsed[s];
        }
        delete[] historyUsed;
    }
    if(toEvictAddresses){
        delete toEvictAddresses;
    }
    if (dirtystatus){
        for (uint32_t i = 0; i < countsets; i++){
            if (dirtystatus[i]){
                delete[] dirtystatus[i];
            }
        }
        delete[] dirtystatus;
    }
}

uint64_t CacheLevel::CountColdMisses(){
    return (countsets * associativity);
}

void CacheLevel::Print(ofstream& f, uint32_t sysid){
    f << TAB << dec << sysid
      << TAB << dec << level
      << TAB << dec << size
      << TAB << dec << associativity
      << TAB << dec << linesize
      << TAB << ReplacementPolicyNames[replpolicy]
      << TAB << TypeString()
      << ENDL;
}

uint64_t CacheLevel::GetStorage(uint64_t addr){
    return (addr >> linesizeBits);
}

uint32_t CacheLevel::GetSet(uint64_t store){
    //if(size == 32768) return store % 64;
    //else if(size == 262144) return store % 512; // FIXME
    return (store % countsets);
}

uint32_t CacheLevel::LineToReplace(uint32_t setid){
    if (replpolicy == ReplacementPolicy_nmru){
        return (recentlyUsed[setid] + 1) % associativity;
    } else if (replpolicy == ReplacementPolicy_trulru){
        return recentlyUsed[setid];
    } else if (replpolicy == ReplacementPolicy_random){
        // FIXME Give a class a randomizer
        Randomizer r;
        return r.RandomInt(associativity);
    } else if (replpolicy == ReplacementPolicy_direct){
        return 0;
    } else {
        assert(0);
    }
    return 0;
}

bool HighlyAssociativeCacheLevel::GetDirtyStatus(
  uint32_t setid,uint32_t lineid,uint64_t store){
    {
        if( fastcontentsdirty[setid]->count(store) > 0 )
            return (*(fastcontentsdirty[setid]))[store]; //.second; 
        else
            return false; // Since it is a miss, it cannot be dirty!
    }        
}

void HighlyAssociativeCacheLevel::SetDirty(
  uint32_t setid, uint32_t lineid, uint64_t store){

    (*(fastcontentsdirty[setid]))[lineid]=true;
}

void HighlyAssociativeCacheLevel::ResetDirty(
  uint32_t setid, uint32_t lineid, uint64_t store){

    (*(fastcontentsdirty[setid]))[lineid]=false;
}

uint64_t CacheLevel::Replace( uint64_t store, 
  uint32_t setid, uint32_t lineid, uint64_t loadstoreflag){

    uint64_t prev = contents[setid][lineid];

    if(GetDirtyStatus(setid,lineid,prev)){
        toEvict=true;
        toEvictAddresses->push_back(prev);
    }
    // Since the new address 'store' has been loaded just now and is not
    // touched yet, we can reset the dirty flag if it is indeed dirty!
    contents[setid][lineid] = store;
    if(loadStoreLogging){
        //TODO figure out if we use this
        if(loadstoreflag)
            ResetDirty(setid,lineid,store);
        else
            SetDirty(setid,lineid,store);
    }

    MarkUsed(setid, lineid, loadstoreflag);  
    return prev;
}

uint64_t HighlyAssociativeCacheLevel::Replace(
  uint64_t store, uint32_t setid, uint32_t lineid, uint64_t loadstoreflag){

    uint64_t prev = contents[setid][lineid];
    contents[setid][lineid] = store;

    pebil_map_type<uint64_t, uint32_t>* fastset = fastcontents[setid];
    if (fastset->count(prev) > 0){
        //assert((*fastset)[prev] == lineid);
        fastset->erase(prev);
    }
    (*fastset)[store] = lineid; //(*fastset)[store].first = lineid;

    if(GetDirtyStatus(setid,lineid,store)){
        toEvict=true;
        toEvictAddresses->push_back(prev);
    }

    if(loadStoreLogging){
        if(loadstoreflag)
            ResetDirty(setid,lineid,store);
        else
            SetDirty(setid,lineid,store);
    }

    MarkUsed(setid, lineid,loadstoreflag);
    return prev;
}

inline void CacheLevel::MarkUsed(
  uint32_t setid, uint32_t lineid, uint64_t loadstoreflag){

    if(loadStoreLogging){
        if(!(loadstoreflag))
            SetDirty(setid,lineid,contents[setid][lineid]);
    }
    if (USES_MARKERS(replpolicy)){
        debug(inform << "level " << dec << level 
          << " USING set " << dec << setid 
          << " line " << lineid << ENDL << flush);
        recentlyUsed[setid] = lineid;
    }
    else if(replpolicy == ReplacementPolicy_trulru) {
        debug(inform << "level " << dec << level 
          << " USING set " << dec << setid 
          << " line " << lineid << ENDL << flush);
        if(recentlyUsed[setid] == lineid)
            recentlyUsed[setid] = historyUsed[setid][lineid].next;
        else {
            historyUsed[setid][historyUsed[setid][lineid].next].prev = historyUsed[setid][lineid].prev;
            historyUsed[setid][historyUsed[setid][lineid].prev].next = historyUsed[setid][lineid].next;
            historyUsed[setid][lineid].prev = historyUsed[setid][recentlyUsed[setid]].prev;
            historyUsed[setid][recentlyUsed[setid]].prev = lineid;
            historyUsed[setid][lineid].next = recentlyUsed[setid];
            historyUsed[setid][historyUsed[setid][lineid].prev].next = lineid;
        }
    }
}

bool HighlyAssociativeCacheLevel::Search(
  uint64_t store, uint32_t* set, uint32_t* lineInSet){

    uint32_t setId = GetSet(store);
    debug(inform << TAB << TAB 
      << "stored " << hex << store 
      << " set " << dec << setId << endl << flush);
    if (set){
        (*set) = setId;
    }

    pebil_map_type<uint64_t, uint32_t>* fastset = fastcontents[setId];
    if (fastset->count(store) > 0){
        if (lineInSet){
            (*lineInSet) = (*fastset)[store];
        }
        return true;
    }

    return false;
}

bool CacheLevel::Search(uint64_t store, uint32_t* set, uint32_t* lineInSet){
    uint32_t setId = GetSet(store);
    debug(inform << TAB << TAB 
      << "stored " << hex << store 
      << " set " << dec << setId << endl << flush);
    if (set){
        (*set) = setId;
    }

    uint64_t* thisset = contents[setId];
    for (uint32_t i = 0; i < associativity; i++){
        if (thisset[i] == store){
            if (lineInSet){
                (*lineInSet) = i;
            }
            return true;
        }
    }

    return false;
}

// TODO: not implemented
bool CacheLevel::MultipleLines(uint64_t addr, uint32_t width){
    return false;
}

void CacheLevel::SetDirty(uint32_t setid, uint32_t lineid,uint64_t store){
    dirtystatus[setid][lineid]=true;
}

void CacheLevel::ResetDirty(uint32_t setid, uint32_t lineid, uint64_t store){
    dirtystatus[setid][lineid]=false;
}

bool CacheLevel::GetDirtyStatus(uint32_t setid, uint32_t lineid, uint64_t 
        store){
    return dirtystatus[setid][lineid];
}

uint32_t CacheLevel::Process(CacheStats* stats, uint32_t memid, uint64_t addr, 
        uint64_t loadstoreflag, bool* anyEvict, void* info) {

    uint32_t set = 0, lineInSet = 0;
    uint64_t store = GetStorage(addr);

    debug(assert(stats));
    debug(assert(stats->Stats));
    debug(assert(stats->Stats[memid]));


    if(loadStoreLogging){
        if(loadstoreflag){
            stats->Stats[memid][level].loadCount++;
        } else{
            stats->Stats[memid][level].storeCount++;
        }         
    }    

    // hit
    if (Search(store, &set, &lineInSet)){
        stats->Stats[memid][level].hitCount++;    
        MarkUsed(set, lineInSet,loadstoreflag);
        return INVALID_CACHE_LEVEL;
    }

    // miss
    EvictionInfo* evicInfo = (EvictionInfo*)info; 
    stats->Stats[memid][level].missCount++;
    uint32_t line2rep = LineToReplace(set);
    uint64_t evictedStore = Replace(store, set, line2rep,
      loadstoreflag);
    evicInfo->level = level;
    evicInfo->addr = evictedStore;
    evicInfo->setid = set;
    evicInfo->lineid = line2rep;
    *anyEvict = true;
    toEvict = true;

    return level + 1;
}

uint32_t CacheLevel::EvictProcess(CacheStats* stats, uint32_t memid, 
        uint64_t addr, uint64_t loadstoreflag, void* info){

    /*  COMMENTING OUT after commit e3e0962 because we are unsure if it is 
        correct 
        uint32_t set = 0, lineInSet = 0;
        uint64_t store = addr;
        debug(assert(stats));
        debug(assert(stats->Stats));
        debug(assert(stats->Stats[memid]));

        if (Search(store, &set, &lineInSet)){
        stats->Stats[memid][level].storeCount++;
        MarkUsed(set, lineInSet,loadstoreflag);
        return INVALID_CACHE_LEVEL;
        } */

    return level + 1;
}

uint32_t ExclusiveCacheLevel::Process(CacheStats* stats, uint32_t memid, 
  uint64_t addr, uint64_t loadstoreflag, bool* anyEvict, void* info){

    uint32_t set = 0;
    uint32_t lineInSet = 0;

    uint64_t store = GetStorage(addr);
    /*  COMMENTING OUT after commit e3e0962 because we are unsure if it is 
        correct 
    // handle victimizing
    EvictionInfo* e = (EvictionInfo*)info; 
    if (e->level != INVALID_CACHE_LEVEL){ 
        set = GetSet(e->addr);
        lineInSet = LineToReplace(set);

        // use the location of the replaced line if the eviction happens to go 
        // to the same set
        if (level == e->level){
            if (e->setid == set){
                lineInSet = e->lineid;
            }
        }

        loadstoreflag = ( 1 & *(anyEvict) );
        *(anyEvict) = GetDirtyStatus(set,lineInSet,e->addr);
        e->addr = Replace(e->addr,set,lineInSet,loadstoreflag);
        toEvict = false;

        if (level == e->level){
            *(anyEvict) = false;
            if(  *(anyEvict)  && ( (level+1) == levelCount )  ) {
                toEvict=true;
                toEvictAddresses->push_back(e->addr);
            }
            return INVALID_CACHE_LEVEL;
        } else {
            return level + 1;
        }
    }

    if(LoadStoreLogging){
        if(loadstoreflag){
            stats->Stats[memid][level].loadCount++;
        }else{
            stats->Stats[memid][level].storeCount++;
        }            
    }

    // hit
    if (Search(store, &set, &lineInSet)){
        stats->Stats[memid][level].hitCount++;

        e->level = level;
        e->addr = store;
        e->setid = set;
        e->lineid = lineInSet;

        toEvict = false;
        if (level == FirstExclusive){
            MarkUsed(set, lineInSet,loadstoreflag);
            return INVALID_CACHE_LEVEL;
        }
        MarkUsed(set, lineInSet,GetDirtyStatus(set,lineInSet,store));
        *(anyEvict) = ( 1 & loadstoreflag);
        return FirstExclusive;
    }

    // miss
    stats->Stats[memid][level].missCount++;
    toEvict = false;
    if (level == LastExclusive){
        e->level = LastExclusive + 1;
        e->addr = store;

        *(anyEvict) = ( 1 & loadstoreflag);
        return FirstExclusive;
    }
    *(anyEvict) = false; */
    return level + 1;
}

uint32_t NonInclusiveCacheLevel::Process(CacheStats* stats, uint32_t memid, 
  uint64_t addr, uint64_t loadstoreflag, bool* anyEvict, void* info){

    uint32_t set = 0;
    uint32_t lineInSet = 0;

    uint64_t store = GetStorage(addr);
    uint32_t toReturn = INVALID_CACHE_LEVEL;
    bool wasHit = false;


    debug(assert(stats));
    debug(assert(stats->Stats));
    debug(assert(stats->Stats[memid]));

    if(loadStoreLogging){
        if(loadstoreflag){
            stats->Stats[memid][level].loadCount++;
        } else{
            stats->Stats[memid][level].storeCount++;
        }         
    }    

    // If we are processing this cache, then a lower cache must have
    // evicted an address. Check if that evicted address is in this cache.
    // Note: This might not be true with multiple noninclusve levels
    EvictionInfo* evicInfo = (EvictionInfo*)info; 
    assert(evicInfo->level == level - 1);
    uint64_t prevEvictedStore = evicInfo->addr;
    uint32_t prevEvictedSet = 0;
    uint32_t prevEvictedLine = 0;
    bool noNeedToReplace = Search(prevEvictedStore, &prevEvictedSet, 
            &prevEvictedLine); 

    // Can't assume that the evicted address will replace the searched
    // address (since assoc isn't necessarily the same)
    // hit
    wasHit = Search(store, &set, &lineInSet);

    if (wasHit) {
        stats->Stats[memid][level].hitCount++;    
        toReturn = INVALID_CACHE_LEVEL;
    } else { //miss
        stats->Stats[memid][level].missCount++;
        toReturn = level + 1;
    }

    // Do we need to replace an address with an address that was evicted by 
    // a lower cache level (because the evicted address was not already here)?
    if (!noNeedToReplace) {
        uint64_t evictedStore = Replace(prevEvictedStore, prevEvictedSet, 
          LineToReplace(prevEvictedSet), loadstoreflag);
        evicInfo->level = level;
        evicInfo->addr = evictedStore;
    } else {
        evicInfo->level = INVALID_CACHE_LEVEL;
    }

    // Lastly, if we had a hit, we need to mark that address as used, unless
    // that address got replaced
    set = 0;
    lineInSet = 0;
    if (wasHit && Search(store, &set, &lineInSet)) {
        MarkUsed(set, lineInSet,loadstoreflag);
    }

    return toReturn;
}

void CacheLevel::EvictDirty(CacheStats* stats, CacheLevel** levels, 
  uint32_t memid, void* info) {

    // Should be only called by InclusiveCache.
    uint64_t victim;

    /*  COMMENTING OUT after commit e3e0962 because we are unsure if it is 
        correct 
        victim=toEvictAddresses->back();    
    // vector "toEvictAddresses" will be empty by the end of this. Vector 
    // was designed to handle 
    toEvictAddresses->pop_back();
    uint32_t next=level+1;
    uint64_t loadstoreflag=0;
     */
    /* next=levels[next]->EvictProcess(stats,memid,victim,loadstoreflag,
       (void*)info);   
       assert( next == INVALID_CACHE_LEVEL); 
    // If assert fails, implies the memory address which was to be evicted was 
    // not found which is violation in an inclusive cache.
    assert(toEvictAddresses->size()==0); // INFO: Should be removed before
    // merging to dev branch, altho this checks a legal case but is it needed?
     */

    /*  COMMENTING OUT after commit e3e0962 because we are unsure if it is 
        correct 
        while(toEvictAddresses->size()){ 
            // To handle cases where an address from Ln is missing in Ln+1 
            // (e.g  missing in L2, found in L1). 
            victim=toEvictAddresses->back();
            toEvictAddresses->pop_back();
            next=level+1;
            loadstoreflag=0;
            if(next<levelCount) {
                next=levels[next]->EvictProcess(stats, memid, victim, loadstoreflag,
                (void*)info);   
            }
            if(next<levelCount){
                inform << "\t Cannot retire victim " << victim << " to level " 
                << (level+1) << " since  it has already been evicted " <<ENDL;
            }
        }

    toEvict=false; */
    return;
}

bool CacheLevel::GetEvictStatus(){
    return toEvict;
}

MainMemory::MainMemory(uint32_t setSize, uint32_t numOfLines, uint32_t lineSize){
    numOfSets = setSize;
    numOfLinesInSet = numOfLines;
    sizeOfLine = lineSize;
    /*writeOuts = new uint32_t*[numOfSets]; //2d array indexed by set and lineInSet
    readIns = new uint32_t*[numOfSets]; //2d array indexed by set and lineInSet
    for(int i=0;i<numOfSets;i++){
        writeOuts[i] = new uint32_t[numOfLinesInSet];
        readIns[i] = new uint32_t[numOfLinesInSet];
        for(int j=0;j<numOfLinesInSet;j++){
            writeOuts[i][j] = 0;
            readIns[i][j] = 0;
        }
    }*/
    if (numOfLines > 1){
        readWritesMap = new NestedHash();
    } else {
        inOutsMap = new EasyHash();
    }
}

MainMemory::MainMemory(MainMemory& mem){
    numOfSets = mem.numOfSets;
    numOfLinesInSet = mem.numOfLinesInSet;
    sizeOfLine = mem.sizeOfLine;
    /*writeOuts = new uint32_t*[numOfSets]; //2d array indexed by set and lineInSet
    readIns = new uint32_t*[numOfSets]; //2d array indexed by set and lineInSet
    for(int i=0;i<numOfSets;i++){
        writeOuts[i] = new uint32_t[numOfLinesInSet];
        readIns[i] = new uint32_t[numOfLinesInSet];
        for(int j=0;j<numOfLinesInSet;j++){
            writeOuts[i][j] = 0;
            readIns[i][j] = 0;
        }
    }*/
    if (numOfLinesInSet > 1) {
        readWritesMap = new NestedHash();
    } else {
        inOutsMap = new EasyHash();
    }
}

MainMemory::~MainMemory(){
    /*for(int i=0;i<numOfSets;i++){
        delete[] writeOuts[i];
        delete[] readIns[i];
    }
    delete[] writeOuts;
    delete[] readIns;*/
    delete readWritesMap;
    delete inOutsMap;
}

uint32_t MainMemory::GetLoads(){
    uint32_t sum = 0;
    uint32_t* tempP;
    uint32_t tempA[2] = {0, 0};
    tempP = (uint32_t*)tempA;

    if (numOfLinesInSet > 1) {
        for(int i=0;i<numOfSets;i++){
            for(int j=0;j<numOfLinesInSet;j++){
                tempP = readWritesMap->get(i,j,tempP);
                sum += tempP[0];
            }
        }
    } else {
        for(int i=0;i<numOfSets;i++){
            tempP = inOutsMap->get(i, tempP);
            sum += tempP[0];
        }
    }

    return sum;
}

uint32_t MainMemory::GetStores(){
    uint32_t sum = 0;
    uint32_t* tempP;
    uint32_t tempA[2] = {0, 0};
    tempP = (uint32_t*)tempA;

    if (numOfLinesInSet > 1) {
        for(int i=0;i<numOfSets;i++){
            for(int j=0;j<numOfLinesInSet;j++){
                tempP = readWritesMap->get(i,j,tempP);
                sum += tempP[1];
            }
        }
    } else {
        for (int i=0;i<numOfSets;i++){
            tempP = inOutsMap->get(i,tempP);
            sum += tempP[1];
        }
    }

    return sum;
}

CacheStructureHandler::CacheStructureHandler(){
}

void CacheStructureHandler::ExtractAddresses(){
    stringstream tokenizer(description);
    int whichTok=0;
    string token;
    vector<uint64_t> Start;
    vector<uint64_t> End;
    int NumLevelsToken=1;
    int HybridAddressCount=0;

    for ( ; tokenizer >> token; whichTok++){
        if (token.compare(0, 1, "#") == 0){
            break;
        }
        uint64_t Dummy;
        if(whichTok >= (levelCount * 4+ (NumLevelsToken+1))){
            istringstream stream(token);
            stream >> Dummy;
            if(Dummy < 0x1){
                ErrorExit("\n\t The boundary address of Cache structure: "
                  << sysId << " token " << token << " is " << Dummy <<
                  " is not positive!! \n", MetasimError_StringParse);
            } else {
                if(HybridAddressCount%2==0){
                    Start.push_back(Dummy);
                } else {
                    End.push_back(Dummy);
                }                   
                HybridAddressCount+=1;  
            }
        }
    }
    
    if((HybridAddressCount % 2 != 0) || (HybridAddressCount == 0)) {
        warn<<"\n\t NEED TO FEED THIS TO DEBUG/WARNING STREAMS ASAP.";
    }
    
    AddressRangesCount=Start.size() ;// Should be equal to End.size()
    RamAddressStart=(uint64_t*)malloc(AddressRangesCount*sizeof(uint64_t));
    RamAddressEnd=(uint64_t*)malloc(AddressRangesCount*sizeof(uint64_t));

    for(int AddCopy=0; AddCopy < AddressRangesCount ; AddCopy++){
        if(Start[AddCopy]<=End[AddCopy]){
            RamAddressStart[AddCopy]=Start[AddCopy];
            RamAddressEnd[AddCopy]=End[AddCopy];
        } else {
            ErrorExit("\n\t Address range with start: " << Start[AddCopy] <<
              " end: " << End[AddCopy] << " is illegal, starting address is "
              "smaller than ending address ", MetasimError_StringParse);
        }
    }

}

CacheStructureHandler::CacheStructureHandler(CacheStructureHandler& h) {
    sysId = h.sysId;
    levelCount = h.levelCount;
    description.assign(h.description);
    hybridCache=h.hybridCache;
    hits=0;
    misses=0;

    this->LoadStoreLogging = h.LoadStoreLogging;
    this->DirtyCacheHandling = h.DirtyCacheHandling;

#define LVLF(__i, __feature) (h.levels[__i])->Get ## __feature
#define Extract_Level_Args(__i) LVLF(__i, Level()), LVLF(__i, SizeInBytes()), \
  LVLF(__i, Associativity()), LVLF(__i, LineSize()), LVLF(__i, \
  ReplacementPolicy()), LVLF(__i, LoadStoreLog()), LVLF(__i, DirtyCacheHandle())

    levels = new CacheLevel*[levelCount];
    for (uint32_t i = 0; i < levelCount; i++){
        if (LVLF(i, Type()) == CacheLevelType_InclusiveLowassoc){
            InclusiveCacheLevel* l = new InclusiveCacheLevel();
            l->Init(Extract_Level_Args(i));
            levels[i] = l;
            l->SetLevelCount(levelCount);
        } else if (LVLF(i, Type()) == CacheLevelType_NonInclusiveLowassoc){
            NonInclusiveCacheLevel* l = new NonInclusiveCacheLevel();
            l->Init(Extract_Level_Args(i)); 
            inform << "\t Found inclusive " << ENDL;
            levels[i] = l;
            l->SetLevelCount(levelCount);
        } else if (LVLF(i, Type()) == CacheLevelType_InclusiveHighassoc){
            HighlyAssociativeInclusiveCacheLevel* l = new 
              HighlyAssociativeInclusiveCacheLevel();
            l->Init(Extract_Level_Args(i));
            levels[i] = l;
            l->SetLevelCount(levelCount);
        } else if (LVLF(i, Type()) == CacheLevelType_ExclusiveLowassoc){
            ExclusiveCacheLevel* l = new ExclusiveCacheLevel();
            ExclusiveCacheLevel* p = dynamic_cast<ExclusiveCacheLevel*>(
              h.levels[i]);
            assert(p->GetType() == CacheLevelType_ExclusiveLowassoc);
            l->Init(Extract_Level_Args(i), p->FirstExclusive, p->LastExclusive);
            inform << "\t p->LastExclusive " << p->LastExclusive << ENDL;
            levels[i] = l;
            l->SetLevelCount(levelCount);
        } else if (LVLF(i, Type()) == CacheLevelType_ExclusiveHighassoc) {
            HighlyAssociativeExclusiveCacheLevel* l = new 
              HighlyAssociativeExclusiveCacheLevel();
            ExclusiveCacheLevel* p = dynamic_cast<ExclusiveCacheLevel*>(
              h.levels[i]);
            assert(p->GetType() == CacheLevelType_ExclusiveHighassoc);
            l->Init(Extract_Level_Args(i), p->FirstExclusive, p->LastExclusive);
            levels[i] = l;
            l->SetLevelCount(levelCount);
        } else {
            assert(false);
        }
    }
}

bool CacheStructureHandler::CheckRange(CacheStats* stats, uint64_t addr, 
  uint64_t loadstoreflag, uint32_t memid){
    bool AddressNotFound= true; 
    for(int CurrRange=0; (CurrRange < AddressRangesCount) && AddressNotFound; 
      CurrRange++){
        if((addr > RamAddressStart[CurrRange]) && (addr <= 
          RamAddressEnd[CurrRange])) {
            AddressNotFound = false;
            stats->HybridMemStats[memid].hitCount++; 
            if(loadstoreflag)
                stats->HybridMemStats[memid].loadCount++;
            else
                stats->HybridMemStats[memid].storeCount++;
        }
    }

    if(AddressNotFound){
        stats->HybridMemStats[memid].missCount++;     
    }
    return true; // CAUTION: No known use of returning 'bool'!! 
}

void CacheStructureHandler::Print(ofstream& f){
    f << "CacheStructureHandler: "
           << "SysId " << dec << sysId
           << TAB << "Levels " << dec << levelCount
           << ENDL;

    for (uint32_t i = 0; i < levelCount; i++){
        levels[i]->Print(f, sysId);
    }
}

bool CacheStructureHandler::Verify(){
    bool passes = true;
    if (levelCount < 1 || levelCount > 3){
        warn << "Sysid " << dec << sysId
             << " has " << dec << levelCount << " levels."
             << ENDL << flush;
        if (levelCount < 1) {
            passes = false;
        }
    }

    ExclusiveCacheLevel* firstvc = NULL;
    for (uint32_t i = 0; i < levelCount; i++){
        if (levels[i]->IsExclusive()){
            firstvc = dynamic_cast<ExclusiveCacheLevel*>(levels[i]);
            break;
        }
    }

    if (firstvc){
        for (uint32_t i = firstvc->GetLevel(); i <= firstvc->LastExclusive; 
          i++) {
            if (!levels[i]->IsExclusive()){
                warn << "Sysid " << dec << sysId
                     << " level " << dec << i
                     << " should be exclusive."
                     << ENDL << flush;
                passes = false;
            }
            if (levels[i]->GetSetCount() != firstvc->GetSetCount()){
                warn << "Sysid " << dec << sysId
                     << " has exclusive cache levels with different set counts."
                     << ENDL << flush;
                //passes = false;
            }
        }
    }
    return passes;
}

bool CacheStructureHandler::Init(string desc, uint32_t MinimumHighAssociativity, 
	  uint32_t LoadStoreLogging, uint32_t DirtyCacheHandling){
    description = desc;
    this->LoadStoreLogging = LoadStoreLogging;
    this->DirtyCacheHandling = DirtyCacheHandling;

    stringstream tokenizer(description);
    string token;
    uint32_t cacheValues[3];
    ReplacementPolicy repl;

    sysId = 0;
    levelCount = 0;
    hybridCache=-1;

    uint32_t whichTok = 0;
    uint32_t firstExcl = INVALID_CACHE_LEVEL;

    // FIXME - make part of class
    StringParser parser;

    for ( ; (tokenizer >> token) && (whichTok < levelCount * 4+ 2); whichTok++){

        // comment reached on line
        if (token.compare(0, 1, "#") == 0){
            break;
        }

        // 2 special tokens appear first
        if (whichTok == 0){
            if( token.size() > 6){
                if( token.compare(token.size()-6,6,"hybrid")==0) {
                    token.resize(token.size()-6);
                    hybridCache=1;
                }else{
                    hybridCache=0;
                }
            }else{
                hybridCache=0;
            }

            if (!(parser.ParseInt32(token, (int32_t*)(&sysId), 0))){
                return false;
            }
            continue;
        }
        if (whichTok == 1){
            if (!(parser.ParsePositiveInt32(token, &levelCount))){
                return false;
            }
            levels = new CacheLevel*[levelCount];
            continue;
        }

        int32_t idx = (whichTok - 2) % 4;

        // the first 3 numbers for a cache value
        if (idx < 3){
            if (!(parser.ParsePositiveInt32(token, &cacheValues[idx]))){
                return false;
            }
            // the last token for a cache (replacement policy)
        } else {

            // parse replacement policy
            if (token.compare(0, 3, "lru") == 0){
                repl = ReplacementPolicy_nmru;
            } else if (token.compare(0, 4, "rand") == 0){
                repl = ReplacementPolicy_random;
            } else if (token.compare(0, 6, "trulru") == 0){
                repl = ReplacementPolicy_trulru;
            } else if (token.compare(0, 3, "dir") == 0){
                repl = ReplacementPolicy_direct;
            } else {
                return false;
            }
            
            int32_t levelId = (whichTok - 2) / 4;
            bool nonInclusive = false;

            // look for victim cache
            if (token.size() > 3) {
                if (token.compare(token.size() - 3, token.size(), "_vc") == 0){
                    if (firstExcl == INVALID_CACHE_LEVEL){
                        firstExcl = levelId;
                    }
                } else if (token.compare(token.size() - 4, token.size(), 
                  "_sky") == 0){
                      nonInclusive = true;
                } else {
                    if (firstExcl != INVALID_CACHE_LEVEL){
                        warn << "nonsensible structure found in sysid " << sysId << "; using a victim cache for level " << levelId << ENDL << flush;
                    }
                }
            }

            // create cache
            uint32_t sizeInBytes = cacheValues[0];
            uint32_t assoc = cacheValues[1];
            uint32_t lineSize = cacheValues[2];

            if (sizeInBytes < lineSize){
                return false;
            }

            if (assoc >= MinimumHighAssociativity){
                if (firstExcl != INVALID_CACHE_LEVEL){
                    HighlyAssociativeExclusiveCacheLevel* l = new 
                      HighlyAssociativeExclusiveCacheLevel();
                    l->Init(levelId, sizeInBytes, assoc, lineSize, repl, 
					  LoadStoreLogging, DirtyCacheHandling, firstExcl, levelCount - 1);
                    levels[levelId] = (CacheLevel*)l;
                } else if (nonInclusive) {
                    NonInclusiveCacheLevel* l = new NonInclusiveCacheLevel();
                    l->Init(levelId, sizeInBytes, assoc, lineSize, repl, 
					  LoadStoreLogging, DirtyCacheHandling);
                    levels[levelId] = l;
                } else {
                    HighlyAssociativeInclusiveCacheLevel* l = new 
                      HighlyAssociativeInclusiveCacheLevel();
                    l->Init(levelId, sizeInBytes, assoc, lineSize, repl,
					  LoadStoreLogging, DirtyCacheHandling);
                    levels[levelId] = (CacheLevel*)l;
                }
            } else {
                if (firstExcl != INVALID_CACHE_LEVEL){
                    ExclusiveCacheLevel* l = new ExclusiveCacheLevel();
                    l->Init(levelId, sizeInBytes, assoc, lineSize, repl, 
                      LoadStoreLogging, DirtyCacheHandling, firstExcl, levelCount - 1);
                    levels[levelId] = l;
                } else if (nonInclusive) {
                    NonInclusiveCacheLevel* l = new NonInclusiveCacheLevel();
                    l->Init(levelId, sizeInBytes, assoc, lineSize, repl,
					  LoadStoreLogging, DirtyCacheHandling);
                    levels[levelId] = l;
                } else {
                    InclusiveCacheLevel* l = new InclusiveCacheLevel();
                    l->Init(levelId, sizeInBytes, assoc, lineSize, repl,
					  LoadStoreLogging, DirtyCacheHandling);
                    levels[levelId] = l;
                }
            }
        }
    }

    if (whichTok != levelCount * 4 + 2){
        return false;
    }

    isInitialized = true;
    return Verify();
}

CacheStructureHandler::~CacheStructureHandler(){
    if(isInitialized){
        if (levels){
            for (uint32_t i = 0; i < levelCount; i++){
                if (levels[i]){
                    CacheLevel* toDelete = levels[i];
                    delete toDelete;
                }
            }
            delete[] levels;
        }
    }
}

uint32_t CacheStructureHandler::processAddress(void* stats_in, uint64_t address,
  uint64_t memseq, uint8_t loadstoreflag, uint64_t* Mapping) {
    uint32_t next = 0,tmpNext = 0;
    uint64_t victim = address;

    CacheStats* stats = (CacheStats*)stats_in;
    uint8_t initLoadStoreFlag = loadstoreflag;

    bool anyEvict = false;

    EvictionInfo evictInfo;
    evictInfo.level = INVALID_CACHE_LEVEL;
    uint32_t resLevel = 0;

    while (next < levelCount){
        resLevel = next;
        next = levels[next]->Process(stats, memseq, victim, loadstoreflag,
          &anyEvict,(void*)(&evictInfo));
        // If next level is checked, then it should be a miss from current 
        // level, which implies next operation is a load to a next level!!
    }

    if(next == levelCount){ // Missed on last level
        uint32_t evicSet = evictInfo.setid;
        uint32_t evicLine = evictInfo.lineid;
        // write to stats mainMemory
        uint32_t sizeOfLine = stats->mainMemoryStats[Mapping[memseq]]->numOfLinesInSet;
        if (sizeOfLine > 1){
            if(initLoadStoreFlag){ // TODO check this logic
                uint32_t* tempP;
                uint32_t tempA[2] = {1,0}; //TODO this logic goes with the above TODO
                tempP = (uint32_t*) tempA;
                stats->mainMemoryStats[Mapping[memseq]]->readWritesMap->put(evicSet, evicLine, tempP);
            } else {
                uint32_t* tempP;
                uint32_t tempA[2] = {0,1}; // TODO Can i move these outside the top level 
                tempP = (uint32_t*) tempA; // if/else for less space?
                stats->mainMemoryStats[Mapping[memseq]]->readWritesMap->put(evicSet, evicLine, tempP);
            }
        } else {
            if(initLoadStoreFlag) { // TODO check this logic
                uint32_t* tempP;
                uint32_t tempA[2] = {1,0};
                tempP = (uint32_t*)tempA;
                stats->mainMemoryStats[Mapping[memseq]]->inOutsMap->add(evicSet, tempP);
            } else {
                uint32_t* tempP;
                uint32_t tempA[2] = {0,1};
                tempP = (uint32_t*)tempA;
                stats->mainMemoryStats[Mapping[memseq]]->inOutsMap->add(evicSet, tempP);
            }
        }
    }

/*  COMMENTING OUT after commit e3e0962 because we are unsure if it is 
    correct 
    if(DirtyCacheHandling&&anyEvict){
        while( (tmpNext<levelCount) ){
            if(levels[tmpNext]->GetEvictStatus()){
                levels[tmpNext]->EvictDirty(stats, levels, memseq, 
                  (void*)(&evictInfo));
            }
            tmpNext++;
        }
        
    } 
*/
/*  COMMENTING OUT after commit e3e0962 because we are unsure if it is 
    correct 
    if((hybridCache) && (next!=INVALID_CACHE_LEVEL) && (next>=levelCount)){ 
        // Implies miss at LLC 
        CheckRange(stats,victim,loadstoreflag,memseq); 
        uint32_t lastLevel = levelCount-1;
        if(levels[lastLevel]->GetEvictStatus()){
            levels[lastLevel]->EvictDirty(stats, levels, memseq,
              (void*)(&evictInfo));
            vector<uint64_t>* toEvictAddresses = levels[lastLevel]->
              passEvictAddresses();

            while(toEvictAddresses->size()){ 
                // To handle cases where an address from Ln is missing in Ln+1 
                // (e.g  missing in L2, found in L1). 
                victim=toEvictAddresses->back();
                toEvictAddresses->pop_back();
                loadstoreflag=0; // Since its dirty and written back.
                CheckRange(stats,victim,loadstoreflag,memseq); 
            }
        }
        resLevel = levelCount+1;
    }*/ 
    return resLevel;
}

uint32_t CacheStructureHandler::Process(void* stats_in, BufferEntry* access, uint64_t* Mapping){
    if(access->type == MEM_ENTRY) {
        debug(inform << "Processing MEM_ENTRY with address " << hex << 
          (access->address) << "(" << dec << access->memseq << ")" << ENDL);
        return processAddress(stats_in, access->address, access->memseq, 
          access->loadstoreflag, Mapping);
    } else if(access->type == VECTOR_ENTRY) {
        debug(inform << "Processing VECTOR_ENTRY " << ENDL;); 
        // FIXME
        // Unsure how the mask and index vector are being set up. For now,
        // I'm assuming that the last significant bit of the mask corresponds
        // to the first index (indexVector[0]
        // for each index i in indexVector:
        //    load/store base + indexVector[i] * scale
        uint32_t lastReturn = 0;
        uint64_t currAddr;
        uint16_t mask = (access->vectorAddress).mask;

        for (int i = 0; i < (access->vectorAddress).numIndices; i++) {
            if(mask % 2 == 1) {
                currAddr = (access->vectorAddress).base + 
                  (access->vectorAddress).indexVector[i] * 
                  (access->vectorAddress).scale;
                lastReturn = processAddress(stats_in, currAddr, access->memseq, 
                  access->loadstoreflag, Mapping);
            }
            mask = (mask >> 1);
        }
        return lastReturn;
    } 
  /* TO BE IMPLEMENTED LATER
else if(access->type == PREFETCH_ENTRY) {
      if (ExecuteSoftwarePrefetches) {
        return processAddress(stats_in, access->address, access->memseq, access->loadstoreflag);
      }
      else {
        return 0;
      }
   } */
}

