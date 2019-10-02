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

#define _GNU_SOURCE
#include <dlfcn.h>

#include <InstrumentationCommon.hpp>
#include <DataManager.hpp>
#include <DynamicInstrumentation.hpp>
#include <Metasim.hpp>
#include <ThreadedCommon.hpp>
#include <AddressStreamBase.hpp>

#include <AddressStreamLibrary.hpp>
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

// global data

// Tool bools -- Are we running them
// Defaults. They can be modified by env vars (see ReadSettings)
bool runAddressRange = false;
bool runCacheSimulation = true;
bool runReuseDistance = false;
bool runScatterLength = false;
bool runSpatialLocality = false;

// Memory and Reuse handlers -- how many and which tool owns which handler
static uint32_t CountMemoryHandlers = 0;
static uint32_t CountReuseHandlers = 0;
static int32_t AddressRangeIndex = -1;
static int32_t CacheSimulationFirstIndex = -1;
static int32_t CacheSimulationLastIndex = -1;  // Exclusive
static int32_t ReuseDistanceIndex = -1;
static int32_t ScatterLengthIndex = -1;
static int32_t SpatialLocalityIndex = -1;

// should not be used directly. kept here to be cloned by anyone who needs it
static MemoryStreamHandler** MemoryHandlers = NULL;
//static ReuseDistance** ReuseDistanceHandlers = NULL;

// Common tool data
static SamplingMethod* Sampler = NULL;
static DataManager<AddressStreamStats*>* AllData = NULL;
static FastData<AddressStreamStats*, BufferEntry*>* FastStats = NULL;
static set<uint64_t>* NonmaxKeys = NULL;

// Tool-specific data

// Reuse Distance
static uint32_t ReuseWindow = 0;
static uint32_t ReuseBin = 0;

// Spatial Locality
static uint32_t SpatialWindow = 0;
static uint32_t SpatialBin = 0;
static uint32_t SpatialNMAX = 0;


//#define synchronize(__locker) __locker->ReadLock(); for (bool __s = true; \
  __s == true; __locker->UnLock(), __s = false) 

extern "C" {
    // Called at just before image initialization
    void* tool_dynamic_init(uint64_t* count, DynamicInst** dyn, bool* 
      isThreadedModeFlag){
        SAVE_STREAM_FLAGS(cout);
        InitializeDynamicInstrumentation(count, dyn,isThreadedModeFlag);
        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }

    void* tool_mpi_init(){
        return NULL;
    }

    void* tool_thread_init(thread_key_t tid){
        SAVE_STREAM_FLAGS(cout);
        if (AllData){
            if(isThreadedMode())
                AllData->AddThread(tid);
            InitializeSuspendHandler();

            assert(FastStats);
            if(isThreadedMode())
                FastStats->AddThread(tid);
        } else {
            ErrorExit("Calling PEBIL thread initialization library for thread " 
              << hex << tid << " but no images have been initialized.", 
              MetasimError_NoThread);
        }
        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }

    void* tool_thread_fini(thread_key_t tid){
        SAVE_STREAM_FLAGS(cout);
        inform << "Destroying thread " << hex << tid << ENDL;

        // TODO utilizing finished threads is *buggy*
        /*
        synchronize(AllData){
            AllData->FinishThread(tid);
        }
        */
        RESTORE_STREAM_FLAGS(cout);
    }

    // initializes an image
    // The mutex assures that the image is initialized exactly once, especially
    // in the case that multiple threads exist before this image is initialized
    // It should be unnecessary if only a single thread exists because
    // this function kills initialization points
    static pthread_mutex_t image_init_mutex = PTHREAD_MUTEX_INITIALIZER;
    void* tool_image_init(void* s, image_key_t* key, ThreadData* td){
        SAVE_STREAM_FLAGS(cout);
        AddressStreamStats* stats = (AddressStreamStats*)s;

        assert(stats->Initialized == true);

        pthread_mutex_lock(&image_init_mutex);

        // initialize AllData once per address space
        if (AllData == NULL){
            init_signal_handlers();
            ReadSettings();
            AllData = new DataManager<AddressStreamStats*>(GenerateStreamStats, 
              DeleteStreamStats, ReferenceStreamStats);
        }
        assert(AllData);

        // Once per image
        if(AllData->allimages.count(*key) == 0){
            // Initialize image with AllData
            AllData->AddImage(stats, td, *key);

            // Once per address space, initialize FastStats
            // This must be done after AllData has exactly one image, 
            // thread initialized
            if (FastStats == NULL){
                FastStats = new FastData<AddressStreamStats*, BufferEntry*>(
                  GetBufferIds, AllData, BUFFER_CAPACITY(stats));
            }
            assert(FastStats);

            FastStats->AddImage();
            stats->threadid = AllData->GenerateThreadKey();
            stats->imageid = *key;
    
            // Get all dynamic point keys and possibly disable them
            //synchronize(AllData){
                if (NonmaxKeys == NULL){
                    NonmaxKeys = new set<uint64_t>();
                }
    
                set<uint64_t> keys;
                GetAllDynamicKeys(keys);
                for (set<uint64_t>::iterator it = keys.begin(); it != 
                  keys.end(); it++){
                    uint64_t k = (*it);
                    if (GET_TYPE(k) == PointType_bufferfill && 
                      AllData->allimages.count(k) == 0){
                        NonmaxKeys->insert(k);
                    }
                }
    
                if (Sampler->SampleOn == 0){
                    inform << "Disabling all simulation-related instrumentation"
                      " because METASIM_SAMPLE_ON is set to 0" << ENDL;
                    set<uint64_t> AllSimPoints;
                    for (set<uint64_t>::iterator it = NonmaxKeys->begin(); 
                      it != NonmaxKeys->end(); it++){
                        AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
                          PointType_buffercheck));
                        AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
                          PointType_bufferinc));
                        AllSimPoints.insert(GENERATE_KEY(GET_BLOCKID((*it)), 
                          PointType_bufferfill));
                    }
                    SetDynamicPoints(AllSimPoints, false);
                    NonmaxKeys->clear();
                }
    
                AllData->SetTimer(*key, 0);
            //}

            // Kill initialization points for this image
            set<uint64_t> inits;
            inits.insert(*key);
            debug(inform << "Removing init points for image " << hex << (*key) 
              << ENDL);
            SetDynamicPoints(inits, false); 

        }

        pthread_mutex_unlock(&image_init_mutex);

        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }

    static void ProcessBuffer(image_key_t iid, thread_key_t tid, 
      MemoryStreamHandler* handler, uint32_t handlerIndex, 
      uint32_t numElementsInBuffer) {

        uint32_t threadSeq = AllData->GetThreadSequence(tid);
        uint32_t numProcessed = 0;

        AddressStreamStats** faststats = FastStats->GetBufferStats(tid);
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

    static void ProcessReuseBuffer(image_key_t iid, thread_key_t tid, 
      ReuseDistance* rd, uint32_t numElements) {

        uint32_t threadSeq = AllData->GetThreadSequence(tid);
        uint32_t numProcessed = 0;

        AddressStreamStats** faststats = FastStats->GetBufferStats(tid);
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

    static void* process_thread_buffer(image_key_t iid, thread_key_t tid){

#define DONE_WITH_BUFFER(...) BUFFER_CURRENT(stats) = 0;  return NULL;

        assert(iid);
        if (AllData == NULL){
            ErrorExit("data manager does not exist. no images were initialized",
              MetasimError_NoImage);
            return NULL;
        }

        // Buffer is shared between all images
        debug(inform << "Getting data for image " << hex << iid << " thread " 
          << tid << ENDL);
        AddressStreamStats* stats = (AddressStreamStats*)AllData->GetData(iid, 
          tid);
        if (stats == NULL){
            ErrorExit("Cannot retreive image data using key " << dec << iid, 
              MetasimError_NoImage);
            return NULL;
        }

        uint64_t numElements = BUFFER_CURRENT(stats);
        uint64_t capacity = BUFFER_CAPACITY(stats);
        uint32_t threadSeq = AllData->GetThreadSequence(tid);

        debug(inform << "Thread " << hex << tid << TAB << "Image " << hex 
          << iid << TAB << "Counter " << dec << numElements << TAB 
          << "Capacity " << dec << capacity << TAB << "Total " << dec 
          << Sampler->AccessCount << ENDL);

        bool isSampling;
        // Check if we are sampling
        //synchronize(AllData){
            isSampling = Sampler->CurrentlySampling();
            if (NonmaxKeys->empty()){
                AllData->UnLock();
                DONE_WITH_BUFFER();
            }
        //}

        //synchronize(AllData){
            if (isSampling){
                BufferEntry* buffer = &(stats->Buffer[1]);
                // Refresh FastStats so it can be used
                FastStats->Refresh(buffer, numElements, tid);

                // Process the buffer for each memory handler
                for (uint32_t i = 0; i < CountMemoryHandlers; i++) {
                    MemoryStreamHandler* m = stats->Handlers[i];
                    ProcessBuffer(iid, tid, m, i, numElements);
                }

                // Process the buffer for each Reuse Distance handler
                for (uint32_t i = 0; i < CountReuseHandlers; i++) {
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
                AddressStreamStats** faststats = FastStats->GetBufferStats(tid);
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

                    if (Sampler->ExceedsAccessLimit(s->Counters[idx]) ||
                      (Sampler->ExceedsAccessLimit(stats->GroupCounters[gidx]))
                      ) {

                        uint64_t k1 = GENERATE_KEY(gidx, PointType_buffercheck);
                        uint64_t k2 = GENERATE_KEY(gidx, PointType_bufferinc);
                        uint64_t k3 = GENERATE_KEY(gidx, PointType_bufferfill);

                        if (NonmaxKeys->count(k3) > 0){

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

                            NonmaxKeys->erase(k3);
                            assert(NonmaxKeys->count(k3) == 0);
                        }
                    }
                }
                if (MemsRemoved.size()){
                    assert(MemsRemoved.size() % 3 == 0);
                    debug(inform << "REMOVING " << dec << (MemsRemoved.size() 
                      / 3) << " blocks" << ENDL);
                    SuspendAllThreads(AllData->CountThreads(), 
                      AllData->allthreads.begin(), AllData->allthreads.end());
                    SetDynamicPoints(MemsRemoved, false);
                    ResumeAllThreads();
                }

                if (Sampler->SwitchesMode(numElements)){
                    SuspendAllThreads(AllData->CountThreads(), 
                      AllData->allthreads.begin(), AllData->allthreads.end());
                    SetDynamicPoints(*NonmaxKeys, false);
                    ResumeAllThreads();
                }

            } else { // if not sampling
                if (Sampler->SwitchesMode(numElements)){
                    SuspendAllThreads(AllData->CountThreads(), 
                      AllData->allthreads.begin(), AllData->allthreads.end());
                    SetDynamicPoints(*NonmaxKeys, true);
                    ResumeAllThreads();
                }

                // Reuse handlers need to know we passed over addresses
                for (uint32_t i = 0; i < CountReuseHandlers; i++) {
                    ReuseDistance* r = stats->RHandlers[i];
                    r->SkipAddresses(numElements);
                }
            }

            Sampler->IncrementAccessCount(numElements);
        //}

        DONE_WITH_BUFFER();
    }

    // conditionally called at first memop in each block
    void* process_buffer(image_key_t* key){
        // forgo this since we shouldn't be printing anything during production
        SAVE_STREAM_FLAGS(cout);

        image_key_t iid = *key;
        process_thread_buffer(iid, pthread_self());

        RESTORE_STREAM_FLAGS(cout);
    }

    // Called when the application exits. Collect the rest of the addresses in
    // the buffer and create the reports
    void* tool_image_fini(image_key_t* key){
        image_key_t iid = *key;

        AllData->SetTimer(iid, 1);
        SAVE_STREAM_FLAGS(cout);

#ifdef MPI_INIT_REQUIRED
        if (!IsMpiValid()){
            warn << "Process " << dec << getpid() << " did not execute "
              << "MPI_Init, will not print execution count files" << ENDL;
            RESTORE_STREAM_FLAGS(cout);
            return NULL;
        }
#endif

        if (AllData == NULL){
            ErrorExit("data manager does not exist. no images were "
              "initialized", MetasimError_NoImage);
            return NULL;
        }

        AddressStreamStats* stats = (AddressStreamStats*)AllData->GetData(iid,
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
        for (set<thread_key_t>::iterator it = AllData->allthreads.begin(); 
          it != AllData->allthreads.end(); it++){
            process_thread_buffer(iid, (*it));
        }

       
        // Create the Address Range report 
        if (runAddressRange) {
            PrintRangeFile(AllData, Sampler, AddressRangeIndex);
        }
        if (runCacheSimulation) {
            PrintCacheSimulationFile(AllData, Sampler, 
              CacheSimulationFirstIndex, CacheSimulationLastIndex);
        }
        if (runReuseDistance) {
            PrintReuseDistanceFile(AllData, ReuseDistanceIndex);
        }
        if (runScatterLength) {
            PrintSGLengthFile(AllData, Sampler, ScatterLengthIndex);
        }
        if (runSpatialLocality) {
            PrintSpatialLocalityFile(AllData, SpatialLocalityIndex);
        }

        
        double t = (AllData->GetTimer(*key, 1) - AllData->GetTimer(*key, 0));
        inform << "CXXX Total Execution time for instrumented application " 
          << t << ENDL;
        // TODO Is this right?
        double m = (double)(CountMemoryHandlers * Sampler->AccessCount);
        inform << "CXXX - Address Stream Library - Memops simulated per "
          << "second: " << (m/t) << ENDL;
        if(NonmaxKeys){
            delete NonmaxKeys;
        }
        RESTORE_STREAM_FLAGS(cout);
    }

};

void GetBufferIds(BufferEntry* b, image_key_t* i){
    *i = b->imageid;
}

uint64_t ReferenceStreamStats(AddressStreamStats* stats){
    return (uint64_t)stats;
}

void DeleteStreamStats(AddressStreamStats* stats){
    if (!stats->Initialized){
        // TODO: delete buffer only for thread-initialized structures?

        delete[] stats->Counters;

        for (uint32_t i = 0; i < CountMemoryHandlers; i++){
            delete stats->Stats[i];
            delete stats->Handlers[i];
        }
        delete[] stats->Stats;
    }
}

// called for every new image and thread
AddressStreamStats* GenerateStreamStats(AddressStreamStats* stats, uint32_t typ,
  image_key_t iid, thread_key_t tid, image_key_t firstimage){
 
    assert(stats);
    AddressStreamStats* s = stats;

    // allocate Counters contiguously with AddressStreamStats. Since the 
    // address of AddressStreamStats is the address of the thread data, this 
    // allows us to avoid an extra memory ref on Counter updates
    if (typ == AllData->ThreadType){
        AddressStreamStats* s = stats;
        stats = (AddressStreamStats*)malloc(sizeof(AddressStreamStats) + 
          (sizeof(uint64_t) * stats->BlockCount));
        assert(stats);
        memcpy(stats, s, sizeof(AddressStreamStats));
        stats->Initialized = false;
    }
    assert(stats);
    stats->threadid = tid;
    stats->imageid = iid;

    // every thread and image gets its own statistics
    if(stats->MemopCount > stats->BlockCount) {
        stats->AllocCount = stats->MemopCount;
    } else {
        stats->AllocCount = stats->BlockCount;
    }

    // Initialize Memory Handlers
    // There needs to be at least one, otherwise running is a waste of time
    assert((CountMemoryHandlers + CountReuseHandlers) > 0);
    stats->Stats = new StreamStats*[CountMemoryHandlers];
    bzero(stats->Stats, sizeof(StreamStats*) * CountMemoryHandlers);    

    if (runAddressRange) {
        stats->Stats[AddressRangeIndex] = new RangeStats(s->AllocCount);
    }
    // if CacheSimulation --> for loop will not run if no caches
    for (uint32_t i = CacheSimulationFirstIndex; i < CacheSimulationLastIndex; 
      i++) {
        CacheStructureHandler* c = (CacheStructureHandler*)MemoryHandlers[i];
        stats->Stats[i] = new CacheStats(c->levelCount, c->sysId, 
          stats->AllocCount, c->hybridCache);
    }
    if (runScatterLength) {
        stats->Stats[ScatterLengthIndex] = new VectorLengthStats(s->AllocCount);
    }

    if (typ == AllData->ThreadType || (iid == firstimage)){
        stats->Handlers = new MemoryStreamHandler*[CountMemoryHandlers];   
        stats->RHandlers = new ReuseDistance::ReuseDistance*[
          CountReuseHandlers];
    
        // all images within a thread share a set of memory handlers, but they 
        // don't exist for any image
        if (runAddressRange) {
            AddressRangeHandler* p = (AddressRangeHandler*)MemoryHandlers[
              AddressRangeIndex];
            AddressRangeHandler* r = new AddressRangeHandler(*p);
            stats->Handlers[AddressRangeIndex] = r;
        }
        for (uint32_t i = CacheSimulationFirstIndex; i < 
          CacheSimulationLastIndex; i++) {
            CacheStructureHandler* p = (CacheStructureHandler*)
              MemoryHandlers[i];
            CacheStructureHandler* c = new CacheStructureHandler(*p);
            // TODO: Should this be here?
            if(p->hybridCache) {
                c->ExtractAddresses();
            }
            stats->Handlers[i] = c;
        }
        if (runReuseDistance) {
            stats->RHandlers[ReuseDistanceIndex] = new 
              ReuseDistance::ReuseDistance(ReuseWindow, ReuseBin);
        }
        if (runScatterLength) {
            VectorLengthHandler* p = (VectorLengthHandler*)MemoryHandlers[
              ScatterLengthIndex];
            VectorLengthHandler* r = new VectorLengthHandler(*p);
            stats->Handlers[ScatterLengthIndex] = r;
        }
        if (runSpatialLocality) {
            stats->RHandlers[SpatialLocalityIndex] = new 
              SpatialLocality(SpatialWindow, SpatialBin, 
              SpatialNMAX);
        }
    }
    else{
        AddressStreamStats * fs = AllData->GetData(firstimage, tid);
        stats->Handlers = fs->Handlers;
    }

    // each thread gets its own buffer
    if (typ == AllData->ThreadType){
        stats->Buffer = new BufferEntry[BUFFER_CAPACITY(stats) + 1];
        bzero(BUFFER_ENTRY(stats, 0), (BUFFER_CAPACITY(stats) + 1) * 
          sizeof(BufferEntry));
        BUFFER_CAPACITY(stats) = BUFFER_CAPACITY(s);
        BUFFER_CURRENT(stats) = 0;
    } else if (iid != firstimage){
        AddressStreamStats* fs = AllData->GetData(firstimage, tid);
        stats->Buffer = fs->Buffer;
    }

    // each thread/image gets its own counters
    if (typ == AllData->ThreadType){
        uint64_t tmp64 = (uint64_t)(stats) + (uint64_t)(sizeof(
          AddressStreamStats));
        stats->Counters = (uint64_t*)(tmp64);

        // keep all CounterType_instruction in place
        memcpy(stats->Counters, s->Counters, sizeof(uint64_t) * s->BlockCount);
        for (uint32_t i = 0; i < stats->BlockCount; i++){
            if (stats->Types[i] != CounterType_instruction){
                stats->Counters[i] = 0;
            }
        }
    }

    return stats;
}

void ReadSettings(){

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

    // Figure out handler indices
    if (runAddressRange) {
        AddressRangeIndex = CountMemoryHandlers;
        CountMemoryHandlers++;
    }
    vector<CacheStructureHandler*> caches;
    if (runCacheSimulation) {
        CacheSimulationFirstIndex = CountMemoryHandlers;
        caches = ReadCacheSimulationSettings();
        assert(caches.size() > 0);
        CountMemoryHandlers += caches.size();
        CacheSimulationLastIndex = CountMemoryHandlers;
    }
    if (runReuseDistance) {
        ReuseDistanceIndex = CountReuseHandlers;
        CountReuseHandlers++;
    }
    if (runScatterLength) {
        ScatterLengthIndex = CountMemoryHandlers;
        CountMemoryHandlers++;
    }
    if (runSpatialLocality) {
        SpatialLocalityIndex = CountReuseHandlers;
        CountReuseHandlers++;
    }

    // Create Handlers
    MemoryStreamHandler** tmpMem = new MemoryStreamHandler*[
      CountMemoryHandlers];
//    ReuseDistance::ReuseDistance** tmpRD = new ReuseDistance::ReuseDistance*[
//      CountReuseHandlers];
    //for(uint32_t i = 0; i < AddressRangeIndex; ++i) {
    //    tmp[i] = MemoryHandlers[i];
    //}
    //if(MemoryHandlers != NULL) {
    //    delete[] MemoryHandlers;
    //}
    MemoryHandlers = tmpMem;

    if (runAddressRange) {
        MemoryHandlers[AddressRangeIndex] = new AddressRangeHandler();
    }

    if (runCacheSimulation) {
        assert(caches.size() > 0);
        for (int32_t i = 0; i < caches.size(); i++) {
            MemoryHandlers[i + CacheSimulationFirstIndex] = caches[i];
        }
    }

    if (runReuseDistance) {
        if (!ReadEnvUint32("METASIM_REUSE_WINDOW", &ReuseWindow)){
            ReuseWindow = 1;
        }
        if (!ReadEnvUint32("METASIM_REUSE_BIN", &ReuseBin)){
            ReuseBin = 1;
        }
    }

    if (runScatterLength) {
        MemoryHandlers[ScatterLengthIndex] = new VectorLengthHandler();
    }

    if (runSpatialLocality) {
        if (!ReadEnvUint32("METASIM_SPATIAL_WINDOW", &SpatialWindow)){
            SpatialWindow = 1;
        }
        if (!ReadEnvUint32("METASIM_SPATIAL_BIN", &SpatialBin)){
            SpatialBin = 1;
        }
        if (!ReadEnvUint32("METASIM_SPATIAL_NMAX", &SpatialNMAX)){
            SpatialNMAX = ReuseDistance::Infinity;
        }

    }

    uint32_t SampleMax;
    uint32_t SampleOn;
    uint32_t SampleOff;
    if (!ReadEnvUint32("METASIM_SAMPLE_MAX", &SampleMax)){
        SampleMax = DEFAULT_SAMPLE_MAX;
    }
    if (!ReadEnvUint32("METASIM_SAMPLE_OFF", &SampleOff)){
        SampleOff = DEFAULT_SAMPLE_OFF;
    }
    if (!ReadEnvUint32("METASIM_SAMPLE_ON", &SampleOn)){
        SampleOn = DEFAULT_SAMPLE_ON;
    }

    Sampler = new SamplingMethod(SampleMax, SampleOn, SampleOff);
    Sampler->Print();
}


