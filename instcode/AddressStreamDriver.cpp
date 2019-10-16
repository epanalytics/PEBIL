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

// Default Constructor
AddressStreamDriver::AddressStreamDriver() {

    // Only run Cache Simulation by default
    runAddressRange = false;
    runCacheSimulation = true;
    runReuseDistance = false;
    runScatterLength = false;
    runSpatialLocality = false;

    // Create the vector to store the tools
    tools = new vector<AddressStreamTool*>();

    numMemoryHandlers = 0;

    // Create a parser for parsing
    parser = new StringParser();

}

AddressStreamDriver::~AddressStreamDriver() {
    if (sampler)
        delete sampler;
    if (liveInstPointKeys)
        delete liveInstPointKeys;
    if (parser)
        delete parser;
    tools->clear();
    delete tools;
    delete fastData;
}

void AddressStreamDriver::CreateFastData(uint64_t capacity) {
    assert(fastData == NULL);
    fastData = new FastData<AddressStreamStats*, BufferEntry*>(GetBufferIds,
      allData, capacity);
    assert(fastData);
}

void AddressStreamDriver::CreateSamplingMethod() {
    if (sampler != NULL) 
       delete sampler;
    uint32_t sampleMax;
    uint32_t sampleOn;
    uint32_t sampleOff;
    if (!(parser->ReadEnvUint32("METASIM_SAMPLE_MAX", &sampleMax))){
        sampleMax = DEFAULT_SAMPLE_MAX;
    }
    if (!(parser->ReadEnvUint32("METASIM_SAMPLE_OFF", &sampleOff))){
        sampleOff = DEFAULT_SAMPLE_OFF;
    }
    if (!(parser->ReadEnvUint32("METASIM_SAMPLE_ON", &sampleOn))){
        sampleOn = DEFAULT_SAMPLE_ON;
    }

    sampler = new SamplingMethod(sampleMax, sampleOn, sampleOff);
    sampler->Print();
}

void AddressStreamDriver::DeleteAllData() {
    delete allData;
}

bool AddressStreamDriver::HasLiveInstrumentationPoints() {
    // if there are keys, then still live
    return !(liveInstPointKeys->empty());
}

// Should only be called once per image (only one thread should call it)
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
    for (vector<AddressStreamTool*>::iterator it = tools->begin(); it !=
      tools->end(); it++) {
          AddressStreamTool* currentTool = (*it);
          currentTool->FinalizeTool(allData, sampler);
    }
    
    double t = (allData->GetTimer(*key, 1) - allData->GetTimer(*key, 0));
    inform << "CXXX Total Execution time for instrumented application " 
      << t << ENDL;
    // TODO Is this right?
    double m = (double)(GetNumMemoryHandlers() * sampler->GetAccessCount());
    inform << "CXXX - Address Stream Library - Memops simulated per "
      << "second: " << (m/t) << ENDL;
    RESTORE_STREAM_FLAGS(cout);

}

// Should only be called once per driver
void AddressStreamDriver::InitializeAddressStreamDriver(
  DataManager<AddressStreamStats*>* d) {

    // Initialize AllData
    allData = d;

    // Initialize Sampler
    CreateSamplingMethod();

    // Set up the tools!
    SetUpTools();

}

// Initialize the Instrumentation Point Keys
// Requires sampler and allData!
void AddressStreamDriver::InitializeKeys() {
    assert(liveInstPointKeys == NULL);
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

// Meant to only be called once per image (thus only one thread should 
// ever call this)
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
    assert(GetNumMemoryHandlers() > 0);
    stats->Handlers = new MemoryStreamHandler*[GetNumMemoryHandlers()];

    for (vector<AddressStreamTool*>::iterator it = tools->begin(); it !=
      tools->end(); it++) {
          AddressStreamTool* currentTool = (*it);
          currentTool->AddNewHandlers(stats);
    }
}

void AddressStreamDriver::InitializeStatsWithNewStreamStats(AddressStreamStats*
  stats) {
    assert(GetNumMemoryHandlers() > 0);
    // Create a StreamStats object for each test/memory handler
    stats->Stats = new StreamStats*[GetNumMemoryHandlers()];
    bzero(stats->Stats, sizeof(StreamStats*) * GetNumMemoryHandlers());

    for (vector<AddressStreamTool*>::iterator it = tools->begin(); it !=
      tools->end(); it++) {
          AddressStreamTool* currentTool = (*it);
          currentTool->AddNewStreamStats(stats);
    }
}

void AddressStreamDriver::ProcessMemoryBuffer(image_key_t iid, thread_key_t tid,  MemoryStreamHandler* handler, uint32_t handlerIndex, uint32_t 
  numElementsInBuffer) {

    uint32_t threadSeq = allData->GetThreadSequence(tid);
    uint32_t numProcessed = 0;

    AddressStreamStats** faststats = fastData->GetBufferStats(tid);
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
        } else {
            // Let each handler know that addresses were skipped
            for (uint32_t i = 0; i < GetNumMemoryHandlers(); i++) {
                MemoryStreamHandler* m = stats->Handlers[i];
                m->SkipAddresses(numElements);
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
        }

        sampler->IncrementAccessCount(numElements);
    //}

    DONE_WITH_BUFFER();
}

void AddressStreamDriver::SetUpTools() {
    // Check for which tools to use
    uint32_t doAddressRange;
    uint32_t doCacheSimulation;
    uint32_t doReuseDistance;
    uint32_t doScatterGatherLength;
    uint32_t doSpatialLocality;
    if (parser->ReadEnvUint32("METASIM_ADDRESS_RANGE", &doAddressRange)){
        runAddressRange = (doAddressRange == 0) ? false : true;
    }
    if (parser->ReadEnvUint32("METASIM_CACHE_SIMULATION", &doCacheSimulation)){
        runCacheSimulation = (doCacheSimulation == 0) ? false : true;
    }
    if (parser->ReadEnvUint32("METASIM_REUSE_DISTANCE", &doReuseDistance)){
        runReuseDistance = (doReuseDistance == 0) ? false : true;
    }
    if (parser->ReadEnvUint32("METASIM_SG_LENGTH", &doScatterGatherLength)){
        runScatterLength = (doScatterGatherLength == 0) ? false : true;
    }
    if (parser->ReadEnvUint32("METASIM_SPATIAL_LOCALITY", &doSpatialLocality)){
        runSpatialLocality = (doSpatialLocality == 0) ? false : true;
    }

    if (runAddressRange) {
        tools->push_back(new AddressRangeTool());
    }

    if (runCacheSimulation) {
        tools->push_back(new CacheSimulationTool());
    }

    if (runReuseDistance) {
        tools->push_back(new ReuseDistanceTool());
    }

    if (runScatterLength) {
        tools->push_back(new ScatterGatherLengthTool());
    }

    if (runSpatialLocality) {
        tools->push_back(new SpatialLocalityTool());
    }

    for (vector<AddressStreamTool*>::iterator it = tools->begin(); it != 
      tools->end(); it++) {
        AddressStreamTool* currentTool = (*it);
        uint32_t handlersAdded = currentTool->CreateHandlers(
          GetNumMemoryHandlers());
        assert(handlersAdded > 0);
        numMemoryHandlers += handlersAdded;
    }
}

// For testing
void AddressStreamDriver::SetParser(StringParser* p) {
    if (parser != NULL)
        delete parser;
    parser = p;
}

void AddressStreamDriver::SetSampler(SamplingMethod* s) {
    if (sampler != NULL)
        delete sampler;
    sampler = s;
}

void GetBufferIds(BufferEntry* b, image_key_t* i){
    *i = b->imageid;
}
