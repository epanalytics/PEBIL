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

#ifdef HAS_EPA_TOOLS
#include <PrefetchSimulation.hpp>
#include <SpatialLocalityPerMemOp.hpp>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <vector>
#include <map>
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
    runHardwarePrefetching = false;
    runReuseDistance = false;
    runScatterLength = false;
    runSpatialLocality = false;
    runSpatialLocalityPerMemOp = false;

    // Create the vector to store the tools
    tools = new vector<AddressStreamTool*>();

    numMemoryHandlers = 0;

    // Create a parser for parsing
    parser = new StringParser();

}

AddressStreamDriver::~AddressStreamDriver() {
    if (sampler != NULL)
        delete sampler;
    if (liveMemoryAccessInstPointKeys != NULL)
        delete liveMemoryAccessInstPointKeys;
    if (dynamicPoints != NULL) {
        delete dynamicPoints;
    }
    if (parser != NULL)
        delete parser;
    for (vector<AddressStreamTool*>::iterator it = tools->begin(); it !=
      tools->end(); it++) {
          delete (*it);
    }
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

AddressStreamTool* AddressStreamDriver::GetTool(uint32_t index) {
    assert(index < GetNumTools());

    return tools->at(index);
}

bool AddressStreamDriver::HasLiveInstrumentationPoints() {
    // if there are keys, then still live
    allData->ReadLock();
    bool stillLive = !(liveMemoryAccessInstPointKeys->empty());
    allData->UnLock();
    return stillLive;
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

// Initialize the Instrumentation Points that the sampler needs to turn off
// Requires sampler and allData!
void AddressStreamDriver::InitializeKeys() {
    if (liveMemoryAccessInstPointKeys == NULL)
        liveMemoryAccessInstPointKeys = new set<uint64_t>();
    assert(liveMemoryAccessInstPointKeys != NULL);

    // Get all the instrumentation points that put memory addresses in the 
    // buffer (PointType_bufferfill) so the sampler can turn them on/off
    set<uint64_t> keys;
    dynamicPoints->GetAllDynamicKeys(keys);
    for (set<uint64_t>::iterator it = keys.begin(); it != keys.end(); it++) {
        uint64_t k = (*it);
        if (GET_TYPE(k) == PointType_bufferfill && 
          allData->allimages.count(k) == 0){
            liveMemoryAccessInstPointKeys->insert(k);
        }
    }

  
    // Disable them if sampling is turned off
    if (sampler->GetSamplingFrequency() == 0){
        inform << "Disabling all simulation-related instrumentation"
          " because METASIM_SAMPLE_ON is set to 0" << ENDL;
        ShutOffInstrumentationInAllBlocks();
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
    dynamicPoints->SetDynamicPoint(GENERATE_KEY(*iid, PointType_inits), false);
}

void* AddressStreamDriver::InitializeNewThread(thread_key_t tid){
    SAVE_STREAM_FLAGS(cout);
    if (allData){
        if(dynamicPoints->IsThreadedMode())
            allData->AddThread(tid);
        InitializeSuspendHandler();

        assert(fastData);
        if(dynamicPoints->IsThreadedMode())
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
    bzero(stats->Handlers, sizeof(MemoryStreamHandler*) * 
      GetNumMemoryHandlers());

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

// Thread-safe function
// Returns number of elements skipped
uint64_t AddressStreamDriver::ProcessBufferForEachHandler(image_key_t iid, 
  thread_key_t tid, uint32_t numElementsInBuffer) {

    //uint32_t threadSeq = allData->GetThreadSequence(tid);
    //uint32_t numProcessed = 0;
    uint64_t numSkipped = 0;
    AddressStreamStats** faststats = fastData->GetBufferStats(tid);
    assert(faststats != NULL);
    uint32_t elementIndex = 0; 
    for (elementIndex = 0; elementIndex < numElementsInBuffer; 
      elementIndex++){
        debug(assert(faststats[elementIndex]));
        debug(assert(faststats[elementIndex]->Stats));

        AddressStreamStats* stats = faststats[elementIndex];
        // If stats is null, then this buffer entry was empty.
        // This is possible when you have multiple threads, and sampling was 
        // turned on/off in the middle
        if (stats == NULL) {
            numSkipped++;
            continue;
        }
        assert(stats != NULL);

        // Process for each memory handler
        for (uint32_t handlerIndex = 0; handlerIndex < GetNumMemoryHandlers(); 
          handlerIndex++) {
            MemoryStreamHandler* handler = stats->Handlers[handlerIndex];
            StreamStats* ss = stats->Stats[handlerIndex];

            BufferEntry* reference = BUFFER_ENTRY(stats, elementIndex);

            if (reference->imageid == 0){
                debug(assert(AllData->CountThreads() > 1));
                continue;
            }

            handler->Process((void*)ss, reference);
      //      numProcessed++;
        }
    }

    return numSkipped;
}

// Thread-safe
// ProcessThreadBuffer
// Input: image ID and thread ID
// Return: none
// Side effects:
//   * The buffer should always be reset (bring "current" back to the front)
//   * If all address collection is shut off, then don't do anything else
//   * If sampling is "on" (collecting addresses), process the buffer through
//     each handlers Process function. Then, check if we should shut off any
//     address collection
//   * If sampling is "off", tell the handlers how many addresses were not 
//     collected
//   * Switch sampling on/off depending on sampler settings
void* AddressStreamDriver::ProcessThreadBuffer(image_key_t iid, thread_key_t 
  tid) {

#define DONE_WITH_BUFFER(...) BUFFER_CURRENT(stats) = 0;  return NULL;

    // Check if we are sampling
    // Thread-safe: Sampling method protected with lock
    bool isSampling;
    isSampling = sampler->CurrentlySampling();

    assert(iid);
    if (allData == NULL){
        ErrorExit("data manager does not exist. no images were initialized",
          MetasimError_NoImage);
        return NULL;
    }

    // Buffer is shared between all images
    debug(inform << "Getting data for image " << hex << iid << " thread " 
      << tid << ENDL);

    // Thread-safe call
    AddressStreamStats* stats = (AddressStreamStats*)allData->GetData(iid, 
      tid);

    // Thread-safe: Each thread has its own stats
    if (stats == NULL){
        ErrorExit("Cannot retreive image data using key " << dec << iid, 
          MetasimError_NoImage);
        return NULL;
    }

    // Thread-safe: Each thread has its own stats
    uint64_t numElements = BUFFER_CURRENT(stats);
    uint64_t capacity = BUFFER_CAPACITY(stats);

    // Thread-safe call
    uint32_t threadSeq = allData->GetThreadSequence(tid);

    debug(inform << "Thread " << hex << tid << TAB << "Image " << hex 
      << iid << TAB << "Counter " << dec << numElements << TAB 
      << "Capacity " << dec << capacity << TAB << "Total " << dec 
      << sampler->AccessCount << ENDL);

    // If there is no more instrumentation, return
    // Thread-Safe call
    if (!HasLiveInstrumentationPoints()){
        DONE_WITH_BUFFER();
    }

    if (isSampling){
        // Refresh FastStats so it can be used
        // Thread-safe call
        BufferEntry* buffer = &(stats->Buffer[1]);
        fastData->Refresh(buffer, numElements, tid);

        // Process the buffer for each memory handler
        // Thread-safe call
        uint64_t numSkipped = ProcessBufferForEachHandler(iid, tid, 
          numElements);
        if (numSkipped > 0) {
            for (uint32_t i = 0; i < GetNumMemoryHandlers(); i++) {
                MemoryStreamHandler* m = stats->Handlers[i];
                m->SkipAddresses(numSkipped);
            }
        }

        // Shut off any instrumentation if sample max is hit
        // Thread-safe: Calls thread-safe functions
        ShutOffInstrumentationInMaxedGroups(iid, tid);

    // if not sampling            
    } else {
        // Let each handler know that addresses were skipped
        // Thread-safe calls since each thread has its own stats/handlers
        for (uint32_t i = 0; i < GetNumMemoryHandlers(); i++) {
            MemoryStreamHandler* m = stats->Handlers[i];
            m->SkipAddresses(numElements);
        }
    }

    // Turn sampling on/off
    // Sampler is thread-safe
    if (sampler->SwitchesMode(numElements)){
        SuspendAllThreads(allData->CountThreads(), 
          allData->allthreads.begin(), allData->allthreads.end());
        dynamicPoints->SetDynamicPoints(*liveMemoryAccessInstPointKeys,
          !(isSampling));
        ResumeAllThreads();
    }

    // Thread-safe
    sampler->IncrementAccessCount(numElements);

    DONE_WITH_BUFFER();
}

void AddressStreamDriver::SetUpTools() {
    // Check for which tools to use
    uint32_t doAddressRange;
    uint32_t doCacheSimulation;
    uint32_t doHardwarePrefetching;
    uint32_t doReuseDistance;
    uint32_t doScatterGatherLength;
    uint32_t doSpatialLocality;
    uint32_t doSpatialLocalityPerMemOp;
    if (parser->ReadEnvUint32("METASIM_ADDRESS_RANGE", &doAddressRange)){
        runAddressRange = (doAddressRange == 0) ? false : true;
    }
    if (parser->ReadEnvUint32("METASIM_CACHE_SIMULATION", &doCacheSimulation)){
        runCacheSimulation = (doCacheSimulation == 0) ? false : true;
    }
    if (parser->ReadEnvUint32("METASIM_HWPF_SIMULATION", 
      &doHardwarePrefetching)){
        runHardwarePrefetching = (doHardwarePrefetching == 0) ? false : true;
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
    if (parser->ReadEnvUint32("METASIM_SPATIAL_LOCALITY_MEMOP", &doSpatialLocalityPerMemOp)){
        runSpatialLocalityPerMemOp = (doSpatialLocalityPerMemOp == 0) ? false : true;
    }

    if (runAddressRange) {
        tools->push_back(new AddressRangeTool());
    }

    if (runCacheSimulation) {
        tools->push_back(new CacheSimulationTool());
    }

    if (runHardwarePrefetching) {
#ifdef HAS_EPA_TOOLS
        tools->push_back(new PrefetchSimulationTool());
#else
        DISPLAY_ERROR << "No hardware prefetching library linked. "
          << "Unset Hardware prefetching library tool. Exitting." << ENDL;
        exit(0);
#endif
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

    if (runSpatialLocalityPerMemOp) {
#ifdef HAS_EPA_TOOLS
        tools->push_back(new SpatialLocalityPerMemOpTool());
#else
        DISPLAY_ERROR << "No spatial locality per memop library linked. "
          << "Unset Spatial locality per memop library tool. Exitting." << ENDL;
        exit(0);
#endif
    }

    for (vector<AddressStreamTool*>::iterator it = tools->begin(); it != 
      tools->end(); it++) {
        AddressStreamTool* currentTool = (*it);
        StringParser parser;
        uint32_t handlersAdded = currentTool->CreateHandlers(
          GetNumMemoryHandlers(), &parser);
        assert(handlersAdded > 0);
        numMemoryHandlers += handlersAdded;
    }
}

void AddressStreamDriver::ShutOffInstrumentationInAllBlocks() {
    // map of imageSequences -> set of blocks to shut off
    map<uint64_t, set<uint64_t>> allBlocks;
    for (set<uint64_t>::iterator it = liveMemoryAccessInstPointKeys->begin();
      it != liveMemoryAccessInstPointKeys->end(); it++) {
        uint32_t blockID = GET_BLOCKID(*it);
        uint32_t imageSequence = GET_IMAGEID(*it);
        (allBlocks[imageSequence]).insert(blockID);
//        allBlocks.insert(GET_BLOCKID(*it));
    }
    for (map<uint64_t, set<uint64_t>>::iterator it = allBlocks.begin();
      it != allBlocks.end(); it++) {
        uint32_t imageSequence = (*it).first;
        image_key_t imageID = allData->GetImageId(imageSequence);
        ShutOffInstrumentationInBlocks(allBlocks[imageSequence], imageID);

    }
}

// Not thread-safe! For performance, thread suspension should happen outside 
// this function
void AddressStreamDriver::ShutOffInstrumentationInBlock(uint64_t blockID, 
  uint64_t imageSequence) {

    // Note: unique keys generated in InitializeDynamicInstrumentation
    set<uint64_t> keysToRemove;
    uint64_t kcheck = GENERATE_UNIQUE_KEY(blockID, imageSequence, 
      PointType_buffercheck);
    uint64_t kinc = GENERATE_UNIQUE_KEY(blockID, imageSequence, 
      PointType_bufferinc);
    uint64_t kfill = GENERATE_UNIQUE_KEY(blockID, imageSequence, 
      PointType_bufferfill);

    // If this key is not active, then done
    if (liveMemoryAccessInstPointKeys->count(kfill) == 0){
        return;
    }

    // Otherwise, remove the instrumentation for this block
    keysToRemove.insert(kcheck);
    keysToRemove.insert(kinc);
    keysToRemove.insert(kfill);
    
    dynamicPoints->SetDynamicPoints(keysToRemove, false);
    liveMemoryAccessInstPointKeys->erase(kfill);

}

void AddressStreamDriver::ShutOffInstrumentationInBlocks(set<uint64_t>& blocks,
  image_key_t iid){
    // Make sure only one thread is executing this code
    SuspendAllThreads(allData->CountThreads(), 
      allData->allthreads.begin(), allData->allthreads.end());

    uint64_t imageSequence = (uint32_t)allData->GetImageSequence(iid);
    
    for (set<uint64_t>::iterator it = blocks.begin(); it != blocks.end(); 
      it++) {
        uint64_t blockID = *it;
        ShutOffInstrumentationInBlock(blockID, imageSequence);
    }

    ResumeAllThreads();
}

void AddressStreamDriver::ShutOffInstrumentationInMaxedGroups(image_key_t iid, 
  thread_key_t tid) {

    // Thread-safe call
    AddressStreamStats* stats = (AddressStreamStats*)allData->GetData(iid, 
      tid);

    // Make sure group counters are up to date
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

    // Can't combine this with above because a later block could cause 
    // group to exceed max
    set<uint64_t> blocksToRemove;
    AddressStreamStats* imageStats;
    for (set<uint64_t>::iterator it = liveMemoryAccessInstPointKeys->begin();
      it != liveMemoryAccessInstPointKeys->end(); it++) {
        uint64_t blockID = GET_BLOCKID(*it);
        image_key_t imageID = allData->GetImageId(GET_IMAGEID(*it));
        imageStats = (AddressStreamStats*)allData->GetData(imageID, tid);
        // If max count is reached, we will remove this block
        uint64_t blocksGroupId = imageStats->GroupIds[blockID]; 
        if (sampler->ExceedsAccessLimit(imageStats->GroupCounters[
          blocksGroupId])) {
            blocksToRemove.insert(blockID);            
        }
    }

    // Only call this if there are blocks to remove since it will suspend 
    // threads
    if (blocksToRemove.size() > 0)
        ShutOffInstrumentationInBlocks(blocksToRemove, iid);
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
