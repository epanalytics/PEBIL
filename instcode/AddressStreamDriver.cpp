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
#include <AddressStreamBase.hpp>
#include <AddressStreamDriver.hpp>

#include <AddressRange.hpp>
#include <CacheSimulation.hpp>
#include <ReuseDistanceASI.hpp>
#include <ScatterGatherLength.hpp>
#include <SpatialLocality.hpp>

#include <ReuseDistance.hpp>   // external: Process Reuse handlers

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

////#define synchronize(__locker) __locker->ReadLock(); for (bool __s = true; \
//  __s == true; __locker->UnLock(), __s = false) 

// Constructor
AddressStreamDriver::AddressStreamDriver(DataManager<AddressStreamStats*>* 
  AllData) {

    // Only run Cache Simulation by default
    runAddressRange = false;
    runCacheSimulation = true;
    runReuseDistance = false;
    runScatterLength = false;
    runSpatialLocality = false;

    // Initialize Memory Handler and Indices
    numReuseHandlers = 0;

    addressRangeIndex = -1;
    cacheSimulationFirstIndex = -1;
    cacheSimulationLastIndex = -1;
    reuseDistanceIndex = -1;
    scatterLengthIndex = -1;
    spatialLocalityIndex = -1;

    // Initialize Tool-specific data
    reuseWindow = 0;
    reuseBin = 0;

    spatialWindow = 0;
    spatialBin = 0;
    spatialNMAX = 0;

    // Initialize AllData
    allData = AllData;

    // Initialize Sampler
    CreateSamplingMethod();

    // Create the temporary Memory Handlers vector
    tempMemoryHandlers = new vector<MemoryStreamHandler*>();

    // Set up the libraries!
    SetUpLibraries();

}

AddressStreamDriver::~AddressStreamDriver() {
    if (sampler)
        delete sampler;
    if (liveInstPointKeys)
        delete liveInstPointKeys;
    tempMemoryHandlers->clear();
    delete tempMemoryHandlers;
    delete fastData;
}

void AddressStreamDriver::CreateFastData(uint64_t capacity) {
    assert(fastData == NULL);
    fastData = new FastData<AddressStreamStats*, BufferEntry*>(GetBufferIds,
      allData, capacity);
    assert(fastData);
}

void AddressStreamDriver::CreateSamplingMethod() {
    assert(sampler == NULL);
    uint32_t sampleMax;
    uint32_t sampleOn;
    uint32_t sampleOff;
    if (!ReadEnvUint32("METASIM_SAMPLE_MAX", &sampleMax)){
        sampleMax = DEFAULT_SAMPLE_MAX;
    }
    if (!ReadEnvUint32("METASIM_SAMPLE_OFF", &sampleOff)){
        sampleOff = DEFAULT_SAMPLE_OFF;
    }
    if (!ReadEnvUint32("METASIM_SAMPLE_ON", &sampleOn)){
        sampleOn = DEFAULT_SAMPLE_ON;
    }

    sampler = new SamplingMethod(sampleMax, sampleOn, sampleOff);
    sampler->Print();
}

// AllData destructor requires # handlers
void AddressStreamDriver::DeleteAllData() {
    delete allData;
}

bool AddressStreamDriver::HasLiveInstrumentationPoints() {
    // if there are keys, then still live
    return !(liveInstPointKeys->empty());
}

void* AddressStreamDriver::FinalizeImage(image_key_t* key) {
    image_key_t iid = *key;

    allData->SetTimer(iid, 1);
    SAVE_STREAM_FLAGS(cout);

#ifdef MPI_INIT_REQUIRED
    if (!IsMpiValid()){
        warn << "Process " << dec << getpid() << " did not execute "
          << "MPI_Init, will not print execution count files" << ENDL;
        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }
#endif

    if (allData == NULL){
        ErrorExit("data manager does not exist. no images were "
          "initialized", MetasimError_NoImage);
        return NULL;
    }

    AddressStreamStats* stats = (AddressStreamStats*)allData->GetData(iid,
      pthread_self());
    if (stats == NULL){
        ErrorExit("Cannot retreive image data using key " << dec << (*key),
          MetasimError_NoImage);
        return NULL;
    }

    // only print stats when the master image exits
    if (!stats->Master){
        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }

    // clear all threads' buffers
    for (set<thread_key_t>::iterator it = allData->allthreads.begin(); 
      it != allData->allthreads.end(); it++) {
        ProcessThreadBuffer(iid, (*it));
    }

    
    // Create the reports 
    if (runAddressRange) {
        PrintRangeFile(allData, sampler, addressRangeIndex);
    }
    if (runCacheSimulation) {
        PrintCacheSimulationFile(allData, sampler, 
          cacheSimulationFirstIndex, cacheSimulationLastIndex);
    }
    if (runReuseDistance) {
        PrintReuseDistanceFile(allData, reuseDistanceIndex);
    }
    if (runScatterLength) {
        PrintSGLengthFile(allData, sampler, scatterLengthIndex);
    }
    if (runSpatialLocality) {
        PrintSpatialLocalityFile(allData, spatialLocalityIndex);
    }

    
    double t = (allData->GetTimer(*key, 1) - allData->GetTimer(*key, 0));
    inform << "CXXX Total Execution time for instrumented application " 
      << t << ENDL;
    // TODO Is this right?
    double m = (double)((numReuseHandlers + tempMemoryHandlers->size()) * 
      sampler->GetAccessCount());
    inform << "CXXX - Address Stream Library - Memops simulated per "
      << "second: " << (m/t) << ENDL;
    RESTORE_STREAM_FLAGS(cout);

}

// Initialize the Instrumentation Point Keys
// Requires sampler and allData!
void AddressStreamDriver::InitializeKeys() {
    assert(liveInstPointKeys == NULL);
    //synchronize(AllData){
    liveInstPointKeys = new set<uint64_t>();

    // Get all the instrumetation points
    set<uint64_t> keys;
    GetAllDynamicKeys(keys);
    for (set<uint64_t>::iterator it = keys.begin(); it != keys.end(); it++) {
        uint64_t k = (*it);
        if (GET_TYPE(k) == PointType_bufferfill && 
          allData->allimages.count(k) == 0){
            liveInstPointKeys->insert(k);
        }
    }

    // Disable them if sampling is turned off
    if (sampler->GetSamplingFrequency() == 0){
        inform << "Disabling all simulation-related instrumentation"
          " because METASIM_SAMPLE_ON is set to 0" << ENDL;
        set<uint64_t> AllSimPoints;
        for (set<uint64_t>::iterator it = liveInstPointKeys->begin(); 
          it != liveInstPointKeys->end(); it++){
            AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
              PointType_buffercheck));
            AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
              PointType_bufferinc));
            AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
              PointType_bufferfill));
        }
        SetDynamicPoints(AllSimPoints, false);
        liveInstPointKeys->clear();
    }

}

void* AddressStreamDriver::InitializeNewImage(image_key_t* iid, 
  AddressStreamStats* stats, ThreadData* threadData){

    // If already added, just return
    if (allData->allimages.count(*iid) != 0) {
        return NULL;
    }

    // Add image to allData
    allData->AddImage(stats, threadData, *iid);

    // If fastData not created yet, create it
    if(fastData == NULL) {
        CreateFastData(BUFFER_CAPACITY(stats));
    }

    // Add image to fastData
    fastData->AddImage();
    
    // Set image and thread id in stats
    stats->imageid = *iid;
    stats->threadid = allData->GenerateThreadKey();

    // Initialize instrumentation point keys for the new image
    InitializeKeys();

    // Start the application timer for this image
    allData->SetTimer(*iid, 0);

    // Remove initialization instrumentation points for this image
    set<uint64_t> inits;
    inits.insert(*iid);
    SetDynamicPoints(inits, false);
}

void* AddressStreamDriver::InitializeNewThread(thread_key_t tid){
    SAVE_STREAM_FLAGS(cout);
    if (allData){
        if(isThreadedMode())
            allData->AddThread(tid);
        InitializeSuspendHandler();

        assert(fastData);
        if(isThreadedMode())
            fastData->AddThread(tid);
    } else {
        ErrorExit("Calling PEBIL thread initialization library for thread " 
          << hex << tid << " but no images have been initialized.", 
          MetasimError_NoThread);
    }
    RESTORE_STREAM_FLAGS(cout);
    return NULL;
}

void AddressStreamDriver::InitializeStatsWithNewHandlers(AddressStreamStats* 
  stats) {
    assert(tempMemoryHandlers->size() + numReuseHandlers > 0);
    stats->Handlers = new MemoryStreamHandler*[tempMemoryHandlers->size()];
    stats->RHandlers = new ReuseDistance*[numReuseHandlers];

    if (runAddressRange) {
        AddressRangeHandler* oldHandler = (AddressRangeHandler*)
          (tempMemoryHandlers->at(addressRangeIndex));
        AddressRangeHandler* newHandler = new AddressRangeHandler(*oldHandler);
        stats->Handlers[addressRangeIndex] = newHandler;
    }

    if (runCacheSimulation) {
        for (uint32_t i = cacheSimulationFirstIndex; i < 
          cacheSimulationLastIndex; i++) {
            CacheStructureHandler* oldHandler = (CacheStructureHandler*)
              (tempMemoryHandlers->at(i));
            CacheStructureHandler* newHandler = new CacheStructureHandler(
              *oldHandler);
            stats->Handlers[i] = newHandler;
        }
    }

    if (runReuseDistance) {
        stats->RHandlers[reuseDistanceIndex] = new ReuseDistance(reuseWindow, 
          reuseBin);
    }

    if (runScatterLength) {
        VectorLengthHandler* oldHandler = (VectorLengthHandler*)
          (tempMemoryHandlers->at(scatterLengthIndex));
        VectorLengthHandler* newHandler = new VectorLengthHandler(*oldHandler);
        stats->Handlers[scatterLengthIndex] = newHandler; 
    }
    
    if (runSpatialLocality) {
        stats->RHandlers[spatialLocalityIndex] = new SpatialLocality(
          spatialWindow, spatialBin, spatialNMAX);
    }
}

void AddressStreamDriver::InitializeStatsWithNewStreamStats(AddressStreamStats*
  stats) {
    assert(tempMemoryHandlers->size() + numReuseHandlers > 0);
    // Create a StreamStats object for each test/memory handler
    stats->Stats = new StreamStats*[tempMemoryHandlers->size()];
    bzero(stats->Stats, sizeof(StreamStats*) * tempMemoryHandlers->size());

    if (runAddressRange) {
        stats->Stats[addressRangeIndex] = new RangeStats(stats->AllocCount);
    }

    if (runCacheSimulation) {
        for (uint32_t i = cacheSimulationFirstIndex; i < 
          cacheSimulationLastIndex; i++) {
            CacheStructureHandler* c = (CacheStructureHandler*)
              (tempMemoryHandlers->at(i));
            stats->Stats[i] = new CacheStats(c->levelCount, c->sysId, 
              stats->AllocCount, c->hybridCache);
        }
    }

    if (runScatterLength) {
        stats->Stats[scatterLengthIndex] = new VectorLengthStats(
          stats->AllocCount);
    }
}

void AddressStreamDriver::ProcessMemoryBuffer(image_key_t iid, thread_key_t tid,  MemoryStreamHandler* handler, uint32_t handlerIndex, uint32_t 
  numElementsInBuffer) {

    uint32_t threadSeq = allData->GetThreadSequence(tid);
    uint32_t numProcessed = 0;

    AddressStreamStats** faststats = fastData->GetBufferStats(tid);
    //assert(faststats[0]->Stats[handlerIndex]->Verify());
    uint32_t elementIndex = 0; 
    for (elementIndex = 0; elementIndex < numElementsInBuffer; 
      elementIndex++){
        debug(assert(faststats[elementIndex]));
        debug(assert(faststats[elementIndex]->Stats));

        AddressStreamStats* stats = faststats[elementIndex];
        StreamStats* ss = stats->Stats[handlerIndex];

        BufferEntry* reference = BUFFER_ENTRY(stats, elementIndex);

        if (reference->imageid == 0){
            debug(assert(AllData->CountThreads() > 1));
            continue;
        }

        handler->Process((void*)ss, reference);
        numProcessed++;
    }
}

void AddressStreamDriver::ProcessReuseBuffer(image_key_t iid, thread_key_t tid, 
  ReuseDistance* rd, uint32_t numElements) {

    uint32_t threadSeq = allData->GetThreadSequence(tid);
    uint32_t numProcessed = 0;

    AddressStreamStats** faststats = fastData->GetBufferStats(tid);
    uint32_t bufcur = 0;
    for (bufcur = 0; bufcur < numElements; bufcur++){
        debug(assert(faststats[bufcur]));
        debug(assert(faststats[bufcur]->Stats));

        AddressStreamStats* stats = faststats[bufcur];

        BufferEntry* reference = BUFFER_ENTRY(stats, bufcur);

        if (reference->imageid == 0){
            debug(assert(AllData->CountThreads() > 1));
            continue;
        }

        ReuseEntry entry = ReuseEntry();
        entry.id = stats->Hashes[stats->BlockIds[reference->memseq]];
        entry.address=reference->address;
        rd->Process(entry);
        numProcessed++;
    }
}

void* AddressStreamDriver::ProcessThreadBuffer(image_key_t iid, thread_key_t 
  tid) {

#define DONE_WITH_BUFFER(...) BUFFER_CURRENT(stats) = 0;  return NULL;

    assert(iid);
    if (allData == NULL){
        ErrorExit("data manager does not exist. no images were initialized",
          MetasimError_NoImage);
        return NULL;
    }

    // Buffer is shared between all images
    debug(inform << "Getting data for image " << hex << iid << " thread " 
      << tid << ENDL);
    AddressStreamStats* stats = (AddressStreamStats*)allData->GetData(iid, 
      tid);
    if (stats == NULL){
        ErrorExit("Cannot retreive image data using key " << dec << iid, 
          MetasimError_NoImage);
        return NULL;
    }

    uint64_t numElements = BUFFER_CURRENT(stats);
    uint64_t capacity = BUFFER_CAPACITY(stats);
    uint32_t threadSeq = allData->GetThreadSequence(tid);

    debug(inform << "Thread " << hex << tid << TAB << "Image " << hex 
      << iid << TAB << "Counter " << dec << numElements << TAB 
      << "Capacity " << dec << capacity << TAB << "Total " << dec 
      << sampler->AccessCount << ENDL);

    bool isSampling;
    // Check if we are sampling
    //synchronize(AllData){
        isSampling = sampler->CurrentlySampling();
        if (!HasLiveInstrumentationPoints()){
            allData->UnLock();
            DONE_WITH_BUFFER();
        }
    //}

    //synchronize(AllData){
        if (isSampling){
            BufferEntry* buffer = &(stats->Buffer[1]);
            // Refresh FastStats so it can be used
            fastData->Refresh(buffer, numElements, tid);

            // Process the buffer for each memory handler
            for (uint32_t i = 0; i < GetNumMemoryHandlers(); i++) {
                MemoryStreamHandler* m = stats->Handlers[i];
                ProcessMemoryBuffer(iid, tid, m, i, numElements);
            }

            // Process the buffer for each Reuse Distance handler
            for (uint32_t i = 0; i < numReuseHandlers; i++) {
                ReuseDistance* r = stats->RHandlers[i];
                ProcessReuseBuffer(iid, tid, r, numElements);
            }        

            // Update the GroupCounters for sampling purposes
            for(uint32_t i = 0; i < (stats->BlockCount); i++) {
                uint32_t idx = i;
                if (stats->Types[i] == CounterType_instruction) {
                    idx = stats->Counters[i];
                }

                uint64_t blocksGroupId = stats->GroupIds[i]; 
                uint64_t blockCount = stats->Counters[idx];
                if(stats->GroupCounters[blocksGroupId] < blockCount) {
                    stats->GroupCounters[blocksGroupId] = blockCount;
                }
            }               
        } 
    //}

    // Turn sampling on/off
    //synchronize(AllData){
        if (isSampling){
            set<uint64_t> MemsRemoved;
            AddressStreamStats** faststats = fastData->GetBufferStats(tid);
            for (uint32_t j = 0; j < numElements; j++){
                AddressStreamStats* s = faststats[j];
                BufferEntry* reference = BUFFER_ENTRY(s, j);

                debug(inform << "Memseq " << dec << reference->memseq << 
                  " has " << s->Stats[0]->GetAccessCount(reference->memseq)
                   << ENDL);

                uint32_t bbid = s->BlockIds[reference->memseq];

                // if max block count is reached, disable all buffer-related
                //  points related to this block
                uint32_t idx = bbid;
                uint32_t gidx = stats->GroupIds[bbid];

                if (s->Types[bbid] == CounterType_instruction){
                    idx = s->Counters[bbid];
                }

                debug(inform << "Slot " << dec << j << TAB << "Thread " 
                  << dec << AllData->GetThreadSequence(pthread_self())
                  << TAB << "Block " << bbid << TAB << "Index " << idx
                  << TAB << "Group " << stats->GroupIds[bbid]
                  << TAB << "Counter " << s->Counters[bbid]
                  << TAB << "Real " << s->Counters[idx]
                  << TAB << "GroupCount " << stats->GroupCounters[gidx] 
                  << ENDL);

                if (sampler->ExceedsAccessLimit(s->Counters[idx]) ||
                  (sampler->ExceedsAccessLimit(stats->GroupCounters[gidx]))
                  ) {

                    uint64_t k1 = GENERATE_KEY(gidx, PointType_buffercheck);
                    uint64_t k2 = GENERATE_KEY(gidx, PointType_bufferinc);
                    uint64_t k3 = GENERATE_KEY(gidx, PointType_bufferfill);

                    if (liveInstPointKeys->count(k3) > 0){

                        if (MemsRemoved.count(k1) == 0){
                            MemsRemoved.insert(k1);
                        }
                        assert(MemsRemoved.count(k1) == 1);

                        if (MemsRemoved.count(k2) == 0){
                            MemsRemoved.insert(k2);
                        }
                        assert(MemsRemoved.count(k2) == 1);

                        if (MemsRemoved.count(k3) == 0){
                            MemsRemoved.insert(k3);
                        }
                        assert(MemsRemoved.count(k3) == 1);

                        liveInstPointKeys->erase(k3);
                        assert(liveInstPointKeys->count(k3) == 0);
                    }
                }
            }
            if (MemsRemoved.size()){
                assert(MemsRemoved.size() % 3 == 0);
                debug(inform << "REMOVING " << dec << (MemsRemoved.size() 
                  / 3) << " blocks" << ENDL);
                SuspendAllThreads(allData->CountThreads(), 
                  allData->allthreads.begin(), allData->allthreads.end());
                SetDynamicPoints(MemsRemoved, false);
                ResumeAllThreads();
            }

            if (sampler->SwitchesMode(numElements)){
                SuspendAllThreads(allData->CountThreads(), 
                  allData->allthreads.begin(), allData->allthreads.end());
                SetDynamicPoints(*liveInstPointKeys, false);
                ResumeAllThreads();
            }

        } else { // if not sampling
            if (sampler->SwitchesMode(numElements)){
                SuspendAllThreads(allData->CountThreads(), 
                  allData->allthreads.begin(), allData->allthreads.end());
                SetDynamicPoints(*liveInstPointKeys, true);
                ResumeAllThreads();
            }

            // Reuse handlers need to know we passed over addresses
            for (uint32_t i = 0; i < numReuseHandlers; i++) {
                ReuseDistance* r = stats->RHandlers[i];
                r->SkipAddresses(numElements);
            }
        }

        sampler->IncrementAccessCount(numElements);
    //}

    DONE_WITH_BUFFER();
}

void AddressStreamDriver::SetUpLibraries() {
    // Check for which libraries to use
    uint32_t AddressRange;
    uint32_t CacheSimulation;
    uint32_t ReuseDistance;
    uint32_t ScatterGatherLength;
    uint32_t SpatialLocality;
    if (ReadEnvUint32("METASIM_ADDRESS_RANGE", &AddressRange)){
        runAddressRange = (AddressRange == 0) ? false : true;
    }
    if (ReadEnvUint32("METASIM_CACHE_SIMULATION", &CacheSimulation)){
        runCacheSimulation = (CacheSimulation == 0) ? false : true;
    }
    if (ReadEnvUint32("METASIM_REUSE_DISTANCE", &ReuseDistance)){
        runReuseDistance = (ReuseDistance == 0) ? false : true;
    }
    if (ReadEnvUint32("METASIM_SG_LENGTH", &ScatterGatherLength)){
        runScatterLength = (ScatterGatherLength == 0) ? false : true;
    }
    if (ReadEnvUint32("METASIM_SPATIAL_LOCALITY", &SpatialLocality)){
        runSpatialLocality = (SpatialLocality == 0) ? false : true;
    }

    // Create temporary handlers for each library that we are running
    // Keep track of which handler corresponds to which library (they will 
    // need to be stored in the same order as in the AddressStreamStats data 
    // structure!)
    if (runAddressRange) {
        addressRangeIndex = tempMemoryHandlers->size();
        tempMemoryHandlers->push_back(new AddressRangeHandler());
    }

    vector<CacheStructureHandler*> caches;
    if (runCacheSimulation) {
        cacheSimulationFirstIndex = tempMemoryHandlers->size();
        caches = ReadCacheSimulationSettings();
        assert(caches.size() > 0);
        for (int32_t i = 0; i < caches.size(); i++) {
            assert((!caches[i]->hybridCache) && "Hybrid cache deprecated");
            tempMemoryHandlers->push_back(caches[i]);
        }
        cacheSimulationLastIndex = tempMemoryHandlers->size();
    }

    if (runReuseDistance) {
        reuseDistanceIndex = numReuseHandlers;
        numReuseHandlers++;

        if (!ReadEnvUint32("METASIM_REUSE_WINDOW", &reuseWindow)){
            reuseWindow = 1;
        }
        if (!ReadEnvUint32("METASIM_REUSE_BIN", &reuseBin)){
            reuseBin = 1;
        }
    }

    if (runScatterLength) {
        scatterLengthIndex = tempMemoryHandlers->size();
        tempMemoryHandlers->push_back(new VectorLengthHandler());
    }

    if (runSpatialLocality) {
        spatialLocalityIndex = numReuseHandlers;
        numReuseHandlers++;

        if (!ReadEnvUint32("METASIM_SPATIAL_WINDOW", &spatialWindow)){
            spatialWindow = 1;
        }
        if (!ReadEnvUint32("METASIM_SPATIAL_BIN", &spatialBin)){
            spatialBin = 1;
        }
        if (!ReadEnvUint32("METASIM_SPATIAL_NMAX", &spatialNMAX)){
            spatialNMAX = ReuseDistance::Infinity;
        }
    }
}


void GetBufferIds(BufferEntry* b, image_key_t* i){
    *i = b->imageid;
}
