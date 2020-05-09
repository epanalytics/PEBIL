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
        stats->Stats[indexInStats + i] = new CacheStats(currHandler->
          GetNumberOfCacheLevels(), currHandler->GetSysId(), stats->AllocCount, 
          false);
        CacheStats* cacheStats = (CacheStats*)stats->Stats[indexInStats 
          + i];
        cacheStats->InitMainMemoryStats(currHandler);
    }
}

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

uint32_t CacheSimulationTool::CreateHandlers(uint32_t index, StringParser* 
  parser){
    indexInStats = index;
    HandleEnvVariables(parser);
    ifstream CacheFile(GetCacheDescriptionFileName());
    return ReadCacheDescription(CacheFile, parser);
}


void CacheSimulationTool::FinalizeTool(DataManager<AddressStreamStats*>* 
  AllData, SamplingMethod* Sampler) {
    AddressStreamStats* stats = AllData->GetData(pthread_self());
    uint32_t numCaches = handlers.size();

    // Create the Cache Simulation Report (.cachesim)
    ofstream MemFile;
    string oFile;
    const char* fileName;

    // dump cache simulation results
    CacheSimulationFileName(stats, oFile);
    fileName = oFile.c_str();
    inform << "Printing cache simulation results to " << fileName << ENDL;
    TryOpen(MemFile, fileName);

    // Create the MainMemoryLogging Report (.memlog)
    ofstream LogFile;
    string lFile;
    const char* logName;

    if(IsKeepingMemoryLog()){
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
    if(IsKeepingMemoryLog()){
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
                    if(IsKeepingMemoryLog()){
                        PrintSysidInfo(LogFile, c, iit);
                    }
                    first = false;
                }

                PrintThreadidInfo(MemFile, thread, AllData);
                if(IsKeepingMemoryLog()){
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

                MemFile<<"\n# Load store stats ";
                if(IsKeepingMemoryLog())
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
                    if(IsKeepingMemoryLog())
                        LogFile << " l" << dec << lvl << "[" << l << "/" 
                          << t << "(" << (ratio)<<")] ";
                }
                if(IsKeepingMemoryLog()) {
                    LogFile << ENDL << "#" << TAB;
                    LogFile << "SetCount: " << dec << 
                      c->mainMemoryStats[0]->numOfSets << TAB << "LineCount: " 
                      << dec << c->mainMemoryStats[0]->numOfLinesInSet;
                }

                MemFile << ENDL;
                if(IsKeepingMemoryLog()){
                    LogFile << ENDL;
                }
            } // for each data manager
        } // for each image
        MemFile << ENDL;
        if(IsKeepingMemoryLog()){
            LogFile << ENDL;
        }
    } // for each cache structure

//    PrintPerBlockCacheSimData(MemFile, AllData);
    MemFile << "# " << "BLK" << TAB << "Sequence" << TAB << "Hashcode" 
      << TAB << "ImageSequence" << TAB << "ThreadId " << ENDL;        
    MemFile << "# " << TAB << "SysId" << TAB << "Level" << TAB 
      << "HitCount" << TAB << "MissCount" << TAB << "LoadCount" << TAB 
      << "StoreCount" << ENDL;

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
                  st->BlockCount, false);

                MainMemory* refMem = s->mainMemoryStats[0];
                c->mainMemoryStats = new MainMemory*[st->BlockCount];
                for (int i=0;i<st->BlockCount;i++){
                    //c->mainMemoryStats[i] = s->mainMemoryStats[i];
                    c->mainMemoryStats[i] = new MainMemory(*refMem);
                }

                aggstats[sys] = c;

                for (uint32_t memid = 0; memid < st->AllocCount; memid++){
                    uint32_t bbid;
                    if (st->PerInstruction){
                        bbid = memid;
                    } else {
                        bbid = st->BlockIds[memid];
                    }

                    for (uint32_t lvl = 0; lvl < c->LevelCount; lvl++) {
                        c->Hit(bbid, lvl, s->GetHits(memid, lvl));
                        c->Miss(bbid, lvl, s->GetMisses(memid, lvl));
                        c->Load(bbid, lvl, s->GetLoads(memid, lvl));
                        c->Store(bbid, lvl, s->GetStores(memid, lvl));
                    } // for each cache level

                    if(IsKeepingMemoryLog()){
                        if( c->mainMemoryStats[0]->numOfLinesInSet > 1) {
                            for(int i = 0; i < c->mainMemoryStats[0]->numOfSets;
                              i++){
                                for(int j = 0; j < 
                                  c->mainMemoryStats[0]->numOfLinesInSet; j++){
                                    NestedHash* CreadInsMap = 
                                      c->mainMemoryStats[bbid]->readInsMap; 
                                    NestedHash* CwriteOutsMap = 
                                      c->mainMemoryStats[bbid]->writeOutsMap;
                                    NestedHash* SreadInsMap = 
                                      s->mainMemoryStats[memid]->readInsMap; 
                                    NestedHash* SwriteOutsMap = 
                                      s->mainMemoryStats[memid]->writeOutsMap;
                                    
                                    uint32_t toAddRead = SreadInsMap->get(i, j);
                                    uint32_t toAddWrite = SwriteOutsMap->get(i,
                                      j);
                                    if (toAddRead > 0){
                                        CreadInsMap->put(i, j, toAddRead);
                                    }
                                    if (toAddWrite > 0){
                                        CwriteOutsMap->put(i, j, toAddWrite);
                                    }
                                }
                            }
                        } else {
                            for(int i=0;i<c->mainMemoryStats[0]->numOfSets;i++){
                                EasyHash* CdirInsMap = 
                                  c->mainMemoryStats[bbid]->dirInsMap;
                                EasyHash* CdirOutsMap = 
                                  c->mainMemoryStats[bbid]->dirOutsMap;
                                EasyHash* SdirInsMap = 
                                  s->mainMemoryStats[memid]->dirInsMap;
                                EasyHash* SdirOutsMap = 
                                  s->mainMemoryStats[memid]->dirOutsMap;

                                uint32_t toAddRead = SdirInsMap->get(i);
                                uint32_t toAddWrite = SdirOutsMap->get(i);
                                if (toAddRead > 0) {
                                    CdirInsMap->add(i, toAddRead);
                                }
                                if (toAddWrite > 0) {
                                    CdirOutsMap->add(i, toAddWrite);
                                }
                            }
                        }
                    }
                } // for each memop

                if(!c->Verify()) {
                    warn << "Failed check on aggregated cache stats" 
                      << ENDL;
                }

            //delete s here
            delete s;
            } // for each cache structure

            CacheStats* root = aggstats[0];
            uint32_t MaxCapacity = root->Capacity;

            if(IsKeepingMemoryLog()) {
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

                if(IsKeepingMemoryLog()){
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

                    //Repeating information in a comment for Pefpal readability
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
                        MemFile << TAB << dec << c->SysId;
                        MemFile << TAB << dec << (lvl+1);
                        MemFile << TAB << dec << c->GetHits(bbid, lvl)
                          << TAB << dec << c->GetMisses(bbid, lvl)
                          << TAB << dec << c->GetLoads(bbid,lvl)
                          << TAB << dec << c->GetStores(bbid,lvl)
                          << ENDL;  
                    }
                    MemFile << TAB << dec << c->SysId;
                    MemFile << TAB << "M"
                      << TAB << dec << c->GetMisses(bbid, c->LevelCount-1)
                      << TAB << dec << 0
                      << TAB << dec << c->mainMemoryStats[bbid]->GetLoads()
                      << TAB << dec << c->mainMemoryStats[bbid]->GetStores()
                      << ENDL; 

                    if (IsKeepingMemoryLog()) {
                        uint32_t numOfSets = c->mainMemoryStats[bbid]->numOfSets;
                        uint32_t numOfLines = c->mainMemoryStats[bbid]->numOfLinesInSet;
                        NestedHash* readInsMap;
                        NestedHash* writeOutsMap;
                        EasyHash* dirInsMap;
                        EasyHash* dirOutsMap;
                        if (numOfLines > 1) {
                            readInsMap = c->mainMemoryStats[bbid]->readInsMap;
                            writeOutsMap = c->mainMemoryStats[bbid]->writeOutsMap;
                        } else {
                            dirInsMap = c->mainMemoryStats[bbid]->dirInsMap;
                            dirOutsMap = c->mainMemoryStats[bbid]->dirOutsMap;
                        }

                        if (numOfLines > 1) {
                            for(int i=0;i<numOfSets;i++){
                                for(int j=0;j<numOfLines;j++){
                                    bool read = readInsMap->contains(i,j);
                                    bool write = writeOutsMap->contains(i,j);
                                    if( read || write) {
                                        LogFile << TAB << bbid << TAB << dec << c->SysId
                                          << TAB << dec << i
                                          << TAB << dec << j;
                                        if (read){
                                            LogFile << TAB << dec << readInsMap->get(i,j);
                                        } else {
                                            LogFile << TAB << "0";
                                        }
                                        if (write){
                                            LogFile << TAB << dec << writeOutsMap->get(i,j);
                                        } else {
                                            LogFile << TAB << "0";
                                        } 
                                        LogFile << ENDL;
                                    }
                                }
                            }
                        }
                        else {
                            for(int i=0;i<numOfSets;i++){
                                bool read = dirInsMap->contains(i);   
                                bool write = dirOutsMap->contains(i);
                                if( read || write) {
                                    LogFile << TAB << bbid << TAB << dec << c->SysId
                                      << TAB << dec << i
                                      << TAB << "0";
                                    if (read) {
                                        LogFile << TAB << dec << dirInsMap->get(i);
                                    } else {
                                        LogFile << TAB << "0";
                                    }
                                    if (write) {
                                        LogFile << TAB << dec << dirOutsMap->get(i);
                                    } else {
                                        LogFile << TAB << "0";
                                    }
                                    LogFile << ENDL;
                                }
                            }
                        }
                    }
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

void CacheSimulationTool::GetAndSetCacheDescriptionFile(StringParser* parser){
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

        CacheDescriptionFile = str;
        return;
    }
    CacheDescriptionFile = knobvalue;
}

// Read variables from the environment
void CacheSimulationTool::HandleEnvVariables(StringParser* parser){

    // When to switch to highly associative cache level
    uint32_t SaveHashMin = MinimumHighAssociativity;
    bool flag = (parser->ReadEnvUint32("METASIM_LIMIT_HIGH_ASSOC", 
      &MinimumHighAssociativity));
    if (!flag){
        MinimumHighAssociativity = SaveHashMin;
    }

    // Should the caches keep track of which lines are dirty?
    uint32_t dirtyStatusCheck = 0;
    if(!(parser->ReadEnvUint32("METASIM_DIRTY_CACHE", &dirtyStatusCheck))){
        dirtyStatusCheck = 0;
    }
    if (dirtyStatusCheck)
        TrackDirtyStatus = true;

    // Should we print a memory log (what parts of memory were read/written - 
    // Note that if dirty cache is OFF, all stores will be considered as writes)
    uint32_t memoryLogCheck = 0;
    if(!(parser->ReadEnvUint32("METASIM_MEMORY_LOG", &memoryLogCheck))){
        memoryLogCheck = 0;
    }
    if (memoryLogCheck)
        KeepMemoryLog = true;

    inform << "Memory Log " << KeepMemoryLog << " Dirty Status "
      << TrackDirtyStatus << ENDL;

    // Get and Set the Cache Description File Name
    GetAndSetCacheDescriptionFile(parser);
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

uint32_t CacheSimulationTool::ReadCacheDescription(istream& cacheStream, 
  StringParser* parser){

    bool streamResult = cacheStream.fail();
    if (streamResult){
        ErrorExit("cannot open cache descriptions file: " << 
          GetCacheDescriptionFileName(), MetasimError_FileOp);
    }

    string line;
    while (getline(cacheStream, line)){
        if (parser->IsEmptyComment(line)){
            continue;
        }
        CacheStructureHandler* c = new CacheStructureHandler(this, parser);
//        c->SetParser(parser);
        if (!c->Init(line)){
            ErrorExit("cannot parse cache description line: " << line, 
              MetasimError_StringParse);
        }
        handlers.push_back(c);
    }
    assert(handlers.size() > 0 && "No cache structures found for simulation");
    return handlers.size();
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
      << "# LoadStoreLogging = " << dec << true << ENDL
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

void CacheSimulationTool::PrintPerBlockCacheSimData(ofstream& MemFile, 
  DataManager<AddressStreamStats*>* AllData){
    MemFile << "# " << "BLK" << TAB << "Sequence" << TAB << "Hashcode" 
      << TAB << "ImageSequence" << TAB << "ThreadId " << ENDL;        
    MemFile << "# " << TAB << "SysId" << TAB << "Level" << TAB 
      << "HitCount" << TAB << "MissCount" << TAB << "LoadCount" << TAB 
      << "StoreCount" << ENDL;
};

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

CacheStats::CacheStats(uint32_t lvl, uint32_t sysid, uint32_t capacity, 
  uint32_t hybridcache){
    LevelCount = lvl;
    SysId = sysid;
    Capacity = capacity;
    mainMemoryStats = new MainMemory*[Capacity];

    levelStats = new LevelStats*[Capacity];

    for (uint32_t i = 0; i < Capacity; i++){
        NewMem(i);
    }
    assert(Verify());
}

CacheStats::~CacheStats(){
    if (levelStats){
        for (uint32_t i = 0; i < Capacity; i++){
            if (levelStats[i]){
                delete[] levelStats[i];
            }
            /*if (mainMemoryStats[i]){
                delete mainMemoryStats[i];
            }*/
        }
        delete[] levelStats;
        //delete[] mainMemoryStats;
    }
}

void CacheStats::InitMainMemoryStats(CacheStructureHandler* handler){
    uint32_t lastLevel = handler->GetNumberOfCacheLevels() - 1;
    CacheLevel* lastCacheLevel = handler->GetCacheLevel(lastLevel);
    uint32_t numOfSets = lastCacheLevel->GetSetCount();
    uint32_t numOfLinesInSet = lastCacheLevel->GetAssociativity();
    uint32_t sizeOfLine = lastCacheLevel->GetLineSize();
    for(int i=0;i<Capacity;i++){
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
    memcpy(nn, levelStats, sizeof(LevelStats*) * Capacity);

    delete[] levelStats;
    levelStats = nn;
}

void CacheStats::NewMem(uint32_t memid){
    assert(memid < Capacity);

    LevelStats* mem = new LevelStats[LevelCount];
    memset(mem, 0, sizeof(LevelStats) * LevelCount);
    levelStats[memid] = mem;
}

void CacheStats::Load(uint32_t memid, uint32_t lvl){
    Load(memid, lvl, 1);
}

void CacheStats::Load(uint32_t memid, uint32_t lvl, uint32_t cnt){
    levelStats[memid][lvl].loadCount += cnt;
}

void CacheStats::Store(uint32_t memid, uint32_t lvl){
    Store(memid, lvl, 1);
}

void CacheStats::Store(uint32_t memid, uint32_t lvl, uint32_t cnt){
    levelStats[memid][lvl].storeCount += cnt;
}

uint64_t CacheStats::GetLoads(uint32_t memid, uint32_t lvl){
    return levelStats[memid][lvl].loadCount;
}

uint64_t CacheStats::GetLoads(uint32_t lvl){
    uint64_t loads = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        loads += levelStats[i][lvl].loadCount;
    }
    return loads;
}

uint64_t CacheStats::GetStores(uint32_t memid, uint32_t lvl){
    return levelStats[memid][lvl].storeCount;
}

uint64_t CacheStats::GetStores(uint32_t lvl){
    uint64_t stores = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        stores += levelStats[i][lvl].storeCount;
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
    levelStats[memid][lvl].missCount += cnt;
}

void CacheStats::Hit(uint32_t memid, uint32_t lvl, uint32_t cnt){
    levelStats[memid][lvl].hitCount += cnt;
}


uint64_t CacheStats::GetHits(uint32_t memid, uint32_t lvl){
    return levelStats[memid][lvl].hitCount;
}

uint64_t CacheStats::GetHits(uint32_t lvl){
    uint64_t hits = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        hits += levelStats[i][lvl].hitCount;
    }
    return hits;
}

uint64_t CacheStats::GetMisses(uint32_t memid, uint32_t lvl){
    return levelStats[memid][lvl].missCount;
}

uint64_t CacheStats::GetMisses(uint32_t lvl){
    uint64_t hits = 0;
    for (uint32_t i = 0; i < Capacity; i++){
        hits += levelStats[i][lvl].missCount;
    }
    return hits;
}

bool CacheStats::HasMemId(uint32_t memid){
    if (memid >= Capacity){
        return false;
    }
    if (levelStats[memid] == NULL){
        return false;
    }
    return true;
}

LevelStats* CacheStats::GetLevelStats(uint32_t memid, uint32_t lvl){
    return &(levelStats[memid][lvl]);
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

// Update levelStats[memid][lvl] with hit (or miss) and load (or store)
void CacheStats::UpdateLevelStats(uint32_t memid, uint32_t lvl, bool hit, 
  bool load) {
    debug(assert(levelStats));
    debug(assert(levelStats[memid]));

    if(hit)
        levelStats[memid][lvl].hitCount++;
    else
        levelStats[memid][lvl].missCount++;

    if(load)
        levelStats[memid][lvl].loadCount++;
    else
        levelStats[memid][lvl].storeCount++;

}

// Update mainMemoryStats[memid] with load (or store) to/from set/line in 
// memory
void CacheStats::UpdateMainMemoryStats(uint32_t memid, uint32_t set, uint32_t
  line, bool load) { 
    if (mainMemoryStats[memid]->sizeOfLine > 1) {
        if(load) 
            mainMemoryStats[memid]->readInsMap->put(set, line, 1);
        else
            mainMemoryStats[memid]->writeOutsMap->put(set, line, 1);
    } else {
        if(load)
            mainMemoryStats[memid]->dirInsMap->add(set, 1);
        else
            mainMemoryStats[memid]->dirOutsMap->add(set, 1);
    }
}

bool CacheStats::Verify(){
    for(uint32_t memid = 0; memid < Capacity; ++memid){

        uint64_t prevMisses = levelStats[memid][0].missCount;

        for(uint32_t level = 1; level < LevelCount; ++level){
            uint64_t hits = levelStats[memid][level].hitCount;
            uint64_t misses = levelStats[memid][level].missCount;
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

/* CacheStructureHandler -- protected functions */
CacheLevel* CacheStructureHandler::ParseCacheLevelTokens(stringstream& 
  tokenizer, uint32_t levelId, uint32_t* firstExclusiveLevel) {
    string token;
    uint32_t cacheValues[3];
    ReplacementPolicy repl;


    for (uint32_t i = 0; i < 3; i++) {
        if(!(tokenizer >> token)) 
            return NULL;
        if (Parser->IsEmptyComment(token))
            return NULL;
        if (!(Parser->ParsePositiveInt32(token, &cacheValues[i])))
            return NULL;
    }

    // the last token for a cache (replacement policy)
    if(!(tokenizer >> token)) 
        return NULL;
    if (Parser->IsEmptyComment(token))
        return NULL;


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
        return NULL;
    }
    
    bool nonInclusive = false;

    // look for special caches
    if (token.size() > 3) {
        if (token.compare(token.size() - 4, token.size(), 
          "_sky") == 0){
              nonInclusive = true;
        }
    }

    // create cache
    uint32_t sizeInBytes = cacheValues[0];
    uint32_t assoc = cacheValues[1];
    uint32_t lineSize = cacheValues[2];

    if (sizeInBytes < lineSize){
        return NULL;
    }

    if (assoc >= GetMinimumHighAssociativity()){
        if (nonInclusive) {
            NonInclusiveCacheLevel* l = new NonInclusiveCacheLevel();
            l->Init(levelId, sizeInBytes, assoc, lineSize, repl,
              IsTrackingDirtyStatus());
            return l;
        } else {
            HighlyAssociativeInclusiveCacheLevel* l = new 
              HighlyAssociativeInclusiveCacheLevel();
            l->Init(levelId, sizeInBytes, assoc, lineSize, repl,
              IsTrackingDirtyStatus());
            return l;
        }
    } else {
        if (nonInclusive) {
            NonInclusiveCacheLevel* l = new NonInclusiveCacheLevel();
            l->Init(levelId, sizeInBytes, assoc, lineSize, repl,
              IsTrackingDirtyStatus());
            return l;
        } else {
            InclusiveCacheLevel* l = new InclusiveCacheLevel();
            l->Init(levelId, sizeInBytes, assoc, lineSize, repl,
              IsTrackingDirtyStatus());
            return l;
        }
    }

    return NULL;
}

uint32_t CacheStructureHandler::ProcessAddress(CacheStats* stats, uint64_t 
  address, uint64_t memseq, uint8_t loadstoreflag) {

    EvictionInfo evictInfo;
    evictInfo.level = INVALID_CACHE_LEVEL;
    uint32_t currLevel = 0;
    uint32_t nextLevel = 0;

    while (nextLevel < LevelCount){
        currLevel = nextLevel;
        nextLevel = Levels[currLevel]->Process(address, loadstoreflag, 
          &evictInfo);

        // Update stats
        bool hit = (nextLevel == INVALID_CACHE_LEVEL);
        stats->UpdateLevelStats(memseq, currLevel, hit, loadstoreflag);
    }

    // If missed on last level, update main memory stats
    if(nextLevel == LevelCount && IsKeepingMemoryLog()) {
        stats->UpdateMainMemoryStats(memseq, evictInfo.setid, evictInfo.lineid,
          loadstoreflag);
    }

    return 0; // No error
}

/* CacheStructureHandler -- public functions */
CacheStructureHandler::CacheStructureHandler(CacheSimulationTool* tool, 
  StringParser* parser) : CacheSimTool(tool), Initialized(false), 
  LevelCount(0), Levels(nullptr), Parser(parser), SysId(0) {

}

// Create a new CacheStructureHandler (new stats) with same base information
CacheStructureHandler::CacheStructureHandler(CacheStructureHandler& h) {
    CacheSimTool = h.CacheSimTool;
    Initialized = true;        // Will create structures that Init creates
    LevelCount = h.LevelCount;
    Parser = NULL;  // Parser not needed anymore; prevent memory weirdness
    SysId = h.SysId;

#define LVLF(__i, __feature) (h.Levels[__i])->Get ## __feature
#define Extract_Level_Args(__i) LVLF(__i, Level()), LVLF(__i, SizeInBytes()), \
  LVLF(__i, Associativity()), LVLF(__i, LineSize()), LVLF(__i, \
  ReplacementPolicy()), LVLF(__i, IsTrackingDirty())

    Levels = new CacheLevel*[LevelCount];
    for (uint32_t i = 0; i < LevelCount; i++){
        if (LVLF(i, Type()) == CacheLevelType_InclusiveLowassoc){
            InclusiveCacheLevel* l = new InclusiveCacheLevel();
            l->Init(Extract_Level_Args(i));
            Levels[i] = l;
            l->SetLevelCount(LevelCount);
        } else if (LVLF(i, Type()) == CacheLevelType_NonInclusiveLowassoc){
            NonInclusiveCacheLevel* l = new NonInclusiveCacheLevel();
            l->Init(Extract_Level_Args(i)); 
            Levels[i] = l;
            l->SetLevelCount(LevelCount);
        } else if (LVLF(i, Type()) == CacheLevelType_InclusiveHighassoc){
            HighlyAssociativeInclusiveCacheLevel* l = new 
              HighlyAssociativeInclusiveCacheLevel();
            l->Init(Extract_Level_Args(i));
            Levels[i] = l;
            l->SetLevelCount(LevelCount);
        } else {
            assert(false);
        }
    }
}

CacheStructureHandler::~CacheStructureHandler(){
    if(Initialized) {
        if (Levels) {
            for (uint32_t i = 0; i < LevelCount; i++) {
                if (Levels[i]) {
                    CacheLevel* toDelete = Levels[i];
                    delete toDelete;
                }
            }
            delete[] Levels;
        }
    }
}

bool CacheStructureHandler::Init(string desc) {
    string description = desc;

    stringstream tokenizer(description);
    string token;
    uint32_t cacheValues[3];
    ReplacementPolicy repl;

    // Parse the cache description line
    // First token is the sysid
    if(!(tokenizer >> token)) 
        return false;
    if (Parser->IsEmptyComment(token))
        return false;
    if (!(Parser->ParseInt32(token, (int32_t*)(&SysId), 0))){
        return false;
    }

    // Second token is the number of cache levels
    if(!(tokenizer >> token)) 
        return false;
    if (Parser->IsEmptyComment(token))
        return false;
    if (!(Parser->ParsePositiveInt32(token, &LevelCount))){
        return false;
    }
    Levels = new CacheLevel*[LevelCount];

    uint32_t levelId = 0;
    uint32_t firstExclusiveLevel = INVALID_CACHE_LEVEL;
    for (levelId = 0; levelId < LevelCount; levelId++) {
        CacheLevel* newLevel = ParseCacheLevelTokens(tokenizer, levelId, 
          &firstExclusiveLevel);
        if (newLevel == NULL)
            return false;
        newLevel->SetLevelCount(LevelCount);
        Levels[levelId] = newLevel;
        // Get rid of any following "notes"
        tokenizer >> std::ws; // skip whitespace
        char nextChar = tokenizer.peek();
        while (!(isdigit(nextChar)) && nextChar != EOF) {
            if (!(tokenizer >> token))
                return false;
            // if not last level and a comment, then bad token
            if (Parser->IsEmptyComment(token)) {
                if (levelId == LevelCount - 1)
                    break;
                else
                    return false;
            }
            tokenizer >> std::ws;
            nextChar = tokenizer.peek();
        }
    }

    if (levelId != LevelCount) {
        return false;
    }

    Initialized = true;
    return Verify();
}

void CacheStructureHandler::Print(ofstream& f){
    f << "CacheStructureHandler: "
           << "SysId " << dec << SysId
           << TAB << "Levels " << dec << LevelCount
           << ENDL;

    for (uint32_t i = 0; i < LevelCount; i++){
        Levels[i]->Print(f, SysId);
    }
}

uint32_t CacheStructureHandler::Process(void* stats_in, BufferEntry* access) {
    CacheStats* stats = (CacheStats*)stats_in;
    if(access->type == MEM_ENTRY) {
        debug(inform << "Processing MEM_ENTRY with address " << hex << 
          (access->address) << "(" << dec << access->memseq << ")" << ENDL);
        return ProcessAddress(stats, access->address, access->memseq, 
          access->loadstoreflag);
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
                lastReturn = ProcessAddress(stats, currAddr, access->memseq, 
                  access->loadstoreflag);
            }
            mask = (mask >> 1);
        }
        return lastReturn;
    } 
  /* TO BE IMPLEMENTED LATER
else if(access->type == PREFETCH_ENTRY) {
      if (ExecuteSoftwarePrefetches) {
        return ProcessAddress(stats_in, access->address, access->memseq, access->loadstoreflag);
      }
      else {
        return 0;
      }
   } */
}

bool CacheStructureHandler::Verify(){
    bool passes = true;
    if (LevelCount < 1 || LevelCount > 3){
        warn << "Sysid " << dec << SysId
             << " has " << dec << LevelCount << " levels."
             << ENDL << flush;
        if (LevelCount < 1) {
            passes = false;
        }
    }

    return passes;
}

/* CacheLevel -- Protected Functions */
// Get the first address in a cache line
uint64_t CacheLevel::GetCacheAddress(uint64_t addr){
    return (addr >> NumBitsUsedPerLine);
}

// Are these cache contents (given the set and line) dirty?
bool CacheLevel::GetDirtyStatus(uint32_t setid, uint32_t lineid) {
    return DirtyStatus[setid][lineid];
}

// Get the set for a given cache address
uint32_t CacheLevel::GetSet(uint64_t cacheAddress){
    return (cacheAddress % NumSets);
}

// Initialize this cache level
void CacheLevel::Init(CacheLevel_Init_Interface) {
    Level = lvl;
    Size = sizeInBytes;
    Associativity = assoc;
    LineSize = lineSz;
    ReplPolicy = pol;
    TrackDirtyStatus = trackDirty;

    NumSets = Size / (LineSize * Associativity);

    NumBitsUsedPerLine = 0;
    while (lineSz > 0){
        NumBitsUsedPerLine++;
        lineSz = (lineSz >> 1);
    }
    NumBitsUsedPerLine--;

    // Declare and initialize Contents
    Contents = new uint64_t*[NumSets];
    for (uint32_t i = 0; i < NumSets; i++){
        Contents[i] = new uint64_t[Associativity];
        memset(Contents[i], 0, sizeof(uint64_t) * Associativity);
    }

    if (TrackDirtyStatus) {
        DirtyStatus = new bool*[NumSets];
        
        // initialized to false i.e. cacheline is not dirty.
        for (uint32_t i = 0; i < NumSets; i++){
            DirtyStatus[i] = new bool[Associativity];
            memset(DirtyStatus[i], 0, sizeof(bool) * Associativity );   
        }
    }

    if (ReplPolicy == ReplacementPolicy_nmru) {
        RecentlyUsed = new uint32_t[NumSets];
        memset(RecentlyUsed, 0, sizeof(uint32_t) * NumSets);
    } else if (ReplPolicy == ReplacementPolicy_trulru) {
        RecentlyUsed = new uint32_t[NumSets];
        memset(RecentlyUsed, 0, sizeof(uint32_t) * NumSets);
        HistoryUsed = new history*[NumSets];
        // Initialze so that 0 is LRU and highest line number is MRU
        for(int s = 0; s < NumSets; ++s) {
            HistoryUsed[s] = new history[assoc];
            HistoryUsed[s][0].prev = assoc-1;
            HistoryUsed[s][0].next = 1;
            for(int a = 1; a < assoc; ++a) {
                HistoryUsed[s][a].prev = a-1;
                HistoryUsed[s][a].next = (a+1)%assoc;
            }
        }
    } else if (ReplPolicy == ReplacementPolicy_random) {
        RanPolicyRandomizer = new Randomizer();
    }
}

// Get the line to evict from the cache for a given set
uint32_t CacheLevel::LineToReplace(uint32_t setid){
    if (ReplPolicy == ReplacementPolicy_nmru){
        return (RecentlyUsed[setid] + 1) % Associativity;
    } else if (ReplPolicy == ReplacementPolicy_trulru){
        return RecentlyUsed[setid];
    } else if (ReplPolicy == ReplacementPolicy_random){
        return RanPolicyRandomizer->RandomInt(Associativity);
    } else if (ReplPolicy == ReplacementPolicy_direct){
        return 0;
    } else {
        assert(0);
    }
    return 0;
}

void CacheLevel::MarkUsed(uint32_t setid, uint32_t lineid) {

    if (ReplPolicy == ReplacementPolicy_nmru){
        debug(inform << "level " << dec << level 
          << " USING set " << dec << setid 
          << " line " << lineid << ENDL << flush);
        RecentlyUsed[setid] = lineid;
    }
    else if(ReplPolicy == ReplacementPolicy_trulru) {
        debug(inform << "level " << dec << level 
          << " USING set " << dec << setid 
          << " line " << lineid << ENDL << flush);
        // If this line was the LRU, then have LRU point to the next least 
        // recently used element. For example:
        // (LRU)  C  B  E  A  D   (MRU)   becomes
        // (LRU)  B  E  A  D  C   (MRU)   if C is used.
        // No need to change next and prev pointers since the head and tail are
        // connected already
        if(RecentlyUsed[setid] == lineid) {
            RecentlyUsed[setid] = HistoryUsed[setid][lineid].next;
        } else {
            // Say we remove E from the following:
            // (LRU)  C  B  E  A  D  (MRU)
            // (prev)               (next)
            // 1. Remove E by resetting the neighbor pointers
            //   (this will be leftNeighbor and rightNeighbor)
            // 2. Move E to end and set it to point to LRU and the old MRU
            // 3. Have the old MRU point to E
            // 4. Have the LRU point to E
            // That should give us:
            // (LRU)  C  B  A  D  E  (MRU)
            // (prev)               (next)
            uint32_t leftNeighbor = HistoryUsed[setid][lineid].prev;
            uint32_t rightNeighbor = HistoryUsed[setid][lineid].next;
            uint32_t theLru = RecentlyUsed[setid];
            uint32_t originalMru = HistoryUsed[setid][theLru].prev;

            HistoryUsed[setid][leftNeighbor].next = rightNeighbor;
            HistoryUsed[setid][rightNeighbor].prev = leftNeighbor;

            HistoryUsed[setid][lineid].prev = originalMru;
            HistoryUsed[setid][lineid].next = theLru;

            HistoryUsed[setid][originalMru].next = lineid;
            HistoryUsed[setid][theLru].prev = lineid;
        }
    }
}

// Replace the contents at the given set and line id with the given 
// cache address. Return the address being replaced.
uint64_t CacheLevel::Replace(uint64_t cacheAddress, uint32_t setid, 
  uint32_t lineid) {

    uint64_t prev = Contents[setid][lineid];
    Contents[setid][lineid] = cacheAddress;
    //MarkUsed(setid, lineid);  
    return prev;
}

// Reset the dirty bit for the given set and line
void CacheLevel::ResetDirty(uint32_t setid, uint32_t lineid) {
    DirtyStatus[setid][lineid] = false;
}

// Look for the given cache address in the cache
// Return the set (and line id if found) and if it was found
bool CacheLevel::Search(uint64_t cacheAddress, uint32_t* set, 
  uint32_t* lineInSet){
    uint32_t setId = GetSet(cacheAddress);
    debug(inform << TAB << TAB << "stored " << hex << cacheAddress
      << " set " << dec << setId << endl << flush);

    // Set the set
    (*set) = setId;

    uint64_t* thisset = Contents[setId];
    for (uint32_t i = 0; i < Associativity; i++){
        // If found, set line id
        if (thisset[i] == cacheAddress){
            (*lineInSet) = i;
            return true;
        }
    }

    return false;
}

// Set the dirty bit for the given set and line
void CacheLevel::SetDirty(uint32_t setid, uint32_t lineid) {
    DirtyStatus[setid][lineid] = true;
}

/* Cache Level -- public functions */
CacheLevel::CacheLevel() : Level(INVALID_CACHE_LEVEL), LevelCount(0), Size(0), 
  Associativity(0), LineSize(0), ReplPolicy(ReplacementPolicy_Undefined), 
  Type(CacheLevelType_Undefined), NumBitsUsedPerLine(0), NumSets(0),
  RanPolicyRandomizer(nullptr), TrackDirtyStatus(false), Contents(nullptr), 
  DirtyStatus(nullptr), HistoryUsed(nullptr), RecentlyUsed(nullptr) {
}

CacheLevel::~CacheLevel(){
    if (RanPolicyRandomizer)
        delete RanPolicyRandomizer;

    if (Contents){
        for (uint32_t i = 0; i < NumSets; i++){
            if (Contents[i]){
                delete[] Contents[i];
            }
        }
        delete[] Contents;
    }

    if (DirtyStatus){
        for (uint32_t i = 0; i < NumSets; i++){
            if (DirtyStatus[i]){
                delete[] DirtyStatus[i];
            }
        }
        delete[] DirtyStatus;
    }

    if (HistoryUsed){
        for(int s = 0; s < NumSets; ++s){
            delete[] HistoryUsed[s];
        }
        delete[] HistoryUsed;
    }

    if (RecentlyUsed){
        delete[] RecentlyUsed;
    }
}

// Print a description of the Cache Level
void CacheLevel::Print(ofstream& f, uint32_t sysid){
    f << TAB << dec << sysid
      << TAB << dec << Level
      << TAB << dec << Size
      << TAB << dec << Associativity
      << TAB << dec << LineSize
      << TAB << ReplacementPolicyNames[ReplPolicy]
      << TAB << TypeString()
      << ENDL;
}

// Process the given address: returns invalid on hit and next level on miss
uint32_t CacheLevel::Process(uint64_t addr, uint64_t loadstoreflag, 
  EvictionInfo* info) {

    uint32_t set = 0, lineInSet = 0;
    uint64_t store = GetCacheAddress(addr); // First address in cache line

    assert(store != 0); // If stored address is 0, then we can't tell if
                        // it was a cold miss (initially it's 0)

    // hit
    if (Search(store, &set, &lineInSet)) {
        MarkUsed(set, lineInSet);
        // If it was a store (and we're tracking dirty lines), then set to dirty
        if (TrackDirtyStatus && !loadstoreflag)
            SetDirty(set, lineInSet);
        return INVALID_CACHE_LEVEL;
    }

    // miss
    EvictionInfo* evicInfo = (EvictionInfo*)info; 
    uint32_t line2rep = LineToReplace(set);
    
    if (TrackDirtyStatus)
        evicInfo->dirty = GetDirtyStatus(set, line2rep);
    else
        evicInfo->dirty = false;

    uint64_t evictedAddr = Replace(store, set, line2rep);
    MarkUsed(set, line2rep);
    // Set/Reset dirty status if we are tracking it
    if (TrackDirtyStatus) {
        if (loadstoreflag) // if load, then not dirty anymore
            ResetDirty(set, line2rep);
        else // if store, then dirty
            SetDirty(set, line2rep);
    }
    evicInfo->level = Level;
    evicInfo->addr = evictedAddr;
    evicInfo->setid = set;
    evicInfo->lineid = line2rep;
    if (evictedAddr)  // cold miss if addr is 0
        evicInfo->coldMiss = false;
    else
        evicInfo->coldMiss = true;

    return Level + 1;
}

// Currently assuming a LL non inclusive cache. The process differs by:
//   1. When a lower cache misses on a given address, it replaces a (replaced)
//      address in the cache
//   2. For a noninclusive cache, we first check to see if the original address 
//      is in the cache. Update hit/miss data based on if this hits/misses
//      2.a Do not mark used (since this address is in L2 now)
//      2.b Mark dirty if hit and store
//   3. Check the cache for the replaced address (the one evicted from L2). If 
//      it was in the cache, then we are done. If it was a miss, then add the 
//      replaced address to the cache level
//      3.a Mark used
//      3.b Mark dirty if L2 had marked it dirty
uint32_t NonInclusiveCacheLevel::Process(uint64_t addr, uint64_t loadstoreflag,
  EvictionInfo* info){

    uint32_t set = 0;
    uint32_t lineInSet = 0;

    uint64_t store = GetCacheAddress(addr);
    uint32_t toReturn = INVALID_CACHE_LEVEL;
    bool wasHit = false;

    // Check to see if the processed address is in the cache and set the return
    // value based on the result (2)
    wasHit = Search(store, &set, &lineInSet);

    if (wasHit) {
        toReturn = INVALID_CACHE_LEVEL;
        if (TrackDirtyStatus && !loadstoreflag) // (2.b)
            SetDirty(set, lineInSet);
    } else { //miss
        toReturn = Level + 1;
    }

    // If we are processing this cache, then a lower cache must have
    // evicted an address. Check if that evicted address is in this cache.
    // Note: This might not be true with multiple noninclusve levels
    EvictionInfo* evicInfo = info; 
    assert(evicInfo->level == Level - 1);
    uint64_t prevEvictedStore = evicInfo->addr;
    uint32_t prevEvictedSet = 0;
    uint32_t prevEvictedLine = 0;
    bool prevDirty = evicInfo->dirty;  // Save previous dirty status
    bool noNeedToReplace = Search(prevEvictedStore, &prevEvictedSet, 
            &prevEvictedLine); 

    set = prevEvictedSet;     // The set and line that is "used"/set dirty
    lineInSet = prevEvictedLine;

    // If this was a hit, then reset eviction information
    if (noNeedToReplace) {
        evicInfo->level = INVALID_CACHE_LEVEL;
        evicInfo->addr = 0;
        evicInfo->setid = INVALID_CACHE_LEVEL;
        evicInfo->lineid = INVALID_CACHE_LEVEL;
        evicInfo->coldMiss = false;
        evicInfo->dirty = false;
    // If it missed, then put it in the cache and set eviction information 
    // to our new evicted address
    } else {
        lineInSet = LineToReplace(set);  // Different line is "used"
        if (TrackDirtyStatus)
            evicInfo->dirty = GetDirtyStatus(set, lineInSet);

        uint64_t evictedStore = Replace(prevEvictedStore, set, lineInSet);

        // Reset the dirty status
        if (TrackDirtyStatus)
            ResetDirty(set, lineInSet);

        evicInfo->level = Level;
        evicInfo->addr = evictedStore;
        evicInfo->setid = set;
        evicInfo->lineid = lineInSet;
        if (evictedStore == 0)
            evicInfo->coldMiss = true;
        else
            evicInfo->coldMiss = false;
    }

    // Mark the hit line or the replaced line as used
    MarkUsed(set, lineInSet);

    // Mark it dirty if the evicted address was dirty
    if (TrackDirtyStatus && prevDirty)
        SetDirty(set, lineInSet);

    return toReturn;
}

uint64_t HighlyAssociativeCacheLevel::Replace(uint64_t cacheAddress, uint32_t 
  setid, uint32_t lineid){

    uint64_t evictedAddress = CacheLevel::Replace(cacheAddress, setid, lineid);

    std::unordered_map<uint64_t, uint32_t>* fastset = FastContents[setid];
    if (fastset->count(evictedAddress) > 0){
        fastset->erase(evictedAddress);
    }
    (*fastset)[cacheAddress] = lineid;

    return evictedAddress;
}

bool HighlyAssociativeCacheLevel::Search(uint64_t cacheAddress, uint32_t* set, 
  uint32_t* lineInSet){

    uint32_t setId = GetSet(cacheAddress);
    debug(inform << TAB << TAB << "stored " << hex << cacheAddress
      << " set " << dec << setId << endl << flush);

    // Set the set
    (*set) = setId;

    // Search the FastContents for the address and set the line
    std::unordered_map<uint64_t, uint32_t>* fastset = FastContents[setId];
    if (fastset->count(cacheAddress) > 0) {
        if (lineInSet) {
            (*lineInSet) = (*fastset)[cacheAddress];
        }
        return true;
    }

    return false;
}

HighlyAssociativeCacheLevel::~HighlyAssociativeCacheLevel() {
    if (FastContents) {
        for (uint32_t i = 0; i < NumSets; i++) {
            if (FastContents[i]) {
                delete FastContents[i];
            }
        }
        delete[] FastContents;
    }
}

void HighlyAssociativeCacheLevel::Init(CacheLevel_Init_Interface) {
    FastContents = new std::unordered_map<uint64_t, uint32_t>*[NumSets];
    for (uint32_t i = 0; i < NumSets; i++) {
        FastContents[i] = new std::unordered_map<uint64_t, uint32_t>();
        FastContents[i]->clear();
    }
}

MainMemory::MainMemory(uint32_t setSize, uint32_t numOfLines, uint32_t lineSize){
    numOfSets = setSize;
    numOfLinesInSet = numOfLines;
    sizeOfLine = lineSize;
    if (numOfLines > 1){
        readInsMap = new NestedHash();
        writeOutsMap = new NestedHash();
    } else {
        dirOutsMap = new EasyHash();
        dirInsMap = new EasyHash();
    }
}

MainMemory::MainMemory(MainMemory& mem){
    numOfSets = mem.numOfSets;
    numOfLinesInSet = mem.numOfLinesInSet;
    sizeOfLine = mem.sizeOfLine;
    if (numOfLinesInSet > 1) {
        readInsMap = new NestedHash();
        writeOutsMap = new NestedHash();
    } else {
        dirInsMap = new EasyHash();
        dirOutsMap = new EasyHash();
    }
}

MainMemory::~MainMemory(){
    delete readInsMap;
    delete writeOutsMap;
    delete dirInsMap;
    delete dirOutsMap;
}

uint32_t MainMemory::GetLoads(){
    uint32_t sum = 0;

    if (numOfLinesInSet > 1) {
        for(int i=0;i<numOfSets;i++){
            for(int j=0;j<numOfLinesInSet;j++){
                sum += readInsMap->get(i,j);
            }
        }
    } else {
        for(int i=0;i<numOfSets;i++){
            sum += dirInsMap->get(i);
        }
    }

    return sum;
}

uint32_t MainMemory::GetStores(){
    uint32_t sum = 0;

    if (numOfLinesInSet > 1) {
        for(int i=0;i<numOfSets;i++){
            for(int j=0;j<numOfLinesInSet;j++){
                sum += writeOutsMap->get(i,j);
            }
        }
    } else {
        for (int i=0;i<numOfSets;i++){
            sum += dirOutsMap->get(i);
        }
    }

    return sum;
}

