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
#include <AddressStreamDriver.hpp>

#include <strings.h>
#include <string.h>

using namespace std;

// global data
static AddressStreamDriver* Driver = NULL;

extern "C" {
    // Create mutex to esnure that dynamicPoints are initialized exactly once
    static pthread_rwlock_t dynamic_init_rwlock = PTHREAD_RWLOCK_INITIALIZER;
    // Called at just before image initialization
    void* tool_dynamic_init(uint64_t* count, DynamicInst** dyn, bool* 
      isThreadedModeFlag){
        pthread_rwlock_wrlock(&dynamic_init_rwlock);
        SAVE_STREAM_FLAGS(cout);
        if (Driver == NULL) {
            Driver = new AddressStreamDriver();
        }
        DynamicInstrumentation* dynamicPoints = Driver->GetDynamicPoints();
        if (dynamicPoints == NULL) {
            dynamicPoints = new DynamicInstrumentation();
            Driver->SetDynamicPoints(dynamicPoints);
        }
        dynamicPoints->InitializeDynamicInstrumentation(count, dyn,
          isThreadedModeFlag);
        RESTORE_STREAM_FLAGS(cout);
        pthread_rwlock_unlock(&dynamic_init_rwlock);
        return NULL;
    }

    void* tool_mpi_init(){
        return NULL;
    }

    void* tool_thread_init(thread_key_t tid){
        if(Driver != NULL)
          return Driver->InitializeNewThread(tid);
        return NULL;
    }

    void* tool_thread_fini(thread_key_t tid){
        SAVE_STREAM_FLAGS(cout);
        inform << "Destroying thread " << hex << tid << ENDL;
        RESTORE_STREAM_FLAGS(cout);
    }

    // initializes an image
    // The mutex assures that the image is initialized exactly once, especially
    // in the case that multiple threads exist before this image is initialized
    // It should be unnecessary if only a single thread exists because
    // this function kills initialization points
    void* tool_image_init(void* s, image_key_t* key, ThreadData* td){
        SAVE_STREAM_FLAGS(cout);
        AddressStreamStats* stats = (AddressStreamStats*)s;

        assert(stats->Initialized == true);

        pthread_rwlock_wrlock(&dynamic_init_rwlock);

        // initialize AllData once per address space
        if (Driver->GetAllData() == NULL){
            init_signal_handlers();
            DataManager<AddressStreamStats*>* AllData;
            AllData = new DataManager<AddressStreamStats*>(GenerateStreamStats, 
              DeleteStreamStats, ReferenceStreamStats);
            Driver->InitializeAddressStreamDriver(AllData);
        }
        assert(Driver);

        Driver->InitializeNewImage(key, stats, td);

        pthread_rwlock_unlock(&dynamic_init_rwlock);

        RESTORE_STREAM_FLAGS(cout);
        return NULL;
    }

    // conditionally called at first memop in each block
    void* process_buffer(image_key_t* key){
        // forgo this since we shouldn't be printing anything during production
        SAVE_STREAM_FLAGS(cout);

        image_key_t iid = *key;
        Driver->ProcessThreadBuffer(iid, pthread_self());

        RESTORE_STREAM_FLAGS(cout);
    }

    // Called when the application exits. Collect the rest of the addresses in
    // the buffer and create the reports
    void* tool_image_fini(image_key_t* key){
        // Only finalize images once
        static bool finalized = false;
        if (finalized)
            return NULL;

        finalized = true;
        Driver->FinalizeImage(key);
        Driver->DeleteAllData();
        delete Driver;
    }

};

uint64_t ReferenceStreamStats(AddressStreamStats* stats){
    return (uint64_t)stats;
}

void DeleteStreamStats(AddressStreamStats* stats){
    if (!stats->Initialized && stats->FirstImage){  // If created for thread
        if (stats->Buffer != NULL)
            delete[] stats->Buffer;
        stats->Buffer = NULL;

        if (Driver->GetNumMemoryHandlers() > 0 && (stats->Stats != NULL)) {
            for (uint32_t i = 0; i < Driver->GetNumMemoryHandlers(); i++) {
                delete stats->Stats[i];
                delete stats->Handlers[i];
            }
            delete[] stats->Stats;
            delete[] stats->Handlers;
        }
        stats->Stats = NULL;
        stats->Handlers = NULL;

        // Counters initialized with stats so memory freed here
        free(stats);
    }
}

// called for every new image and thread
// Initializes and allocates the AddressStreamStats data structure
// NOTE: The write lock should be held before calling this function!
AddressStreamStats* GenerateStreamStats(AddressStreamStats* stats, uint32_t typ,
  image_key_t iid, thread_key_t tid, image_key_t firstimage){
 
    assert(stats);
    AddressStreamStats* s = stats;
    DataManager<AddressStreamStats*>* allData = Driver->GetAllData();

    // Make sure that the write lock was held
    assert(allData->IsWriteLockHeld());
    
    // every thread and image gets its own statistics

    // allocate Counters contiguously with AddressStreamStats. Since the 
    // address of AddressStreamStats is the address of the thread data, this 
    // allows us to avoid an extra memory ref on Counter updates
    if (typ == DataManagerType_Thread) {
        AddressStreamStats* s = stats;
        stats = (AddressStreamStats*)malloc(sizeof(AddressStreamStats) + 
          (sizeof(uint64_t) * stats->BlockCount));
        assert(stats && "Couldn't allocate new stats object");
        memcpy(stats, s, sizeof(AddressStreamStats));
        stats->Initialized = false;
    }
    assert(stats);
    stats->threadid = tid;
    stats->imageid = iid;
    stats->FirstImage = (firstimage == iid);

    if(stats->MemopCount > stats->BlockCount) {
        stats->AllocCount = stats->MemopCount;
    } else {
        stats->AllocCount = stats->BlockCount;
    }

    // Initialize Stream Stats
    Driver->InitializeStatsWithNewStreamStats(stats);

    // Initialize Memory Handlers
    // Modified data generation (from DataManager) to always begin with the 
    // first image. Even if another image spawns the thread, pebil will 
    // GenerateStreamStats for the first image first. This allows us to 
    // initialize data based on whether or not we are the first image, and 
    // allows us to enforce one handler per thread (not per image).
    if ((iid == firstimage)) {
        Driver->InitializeStatsWithNewHandlers(stats);
    } else {
        // Other images would share the handlers
        // Calls ReadLock - Release lock
        allData->UnLock();
        AddressStreamStats* fs = allData->GetData(tid);
        allData->WriteLock();
        stats->Handlers = fs->Handlers;
    }

    // each thread gets its own buffer
    if ((typ == DataManagerType_Thread) && (iid == firstimage)) {
        uint64_t numEntries = BUFFER_CAPACITY(stats);
        stats->Buffer = new BufferEntry[numEntries + 1];
        assert(stats->Buffer && "Couldn't create Buffer");
        bzero(BUFFER_ENTRY(stats, 0), (numEntries) * sizeof(BufferEntry));
        BUFFER_CAPACITY(stats) = BUFFER_CAPACITY(s);
        BUFFER_CURRENT(stats) = 0;
    } else if (iid != firstimage) {
        // Calls ReadLock - Release lock
        allData->UnLock();
        AddressStreamStats* fs = allData->GetData(tid);
        allData->WriteLock();
        stats->Buffer = fs->Buffer;
    }

    // each thread/image gets its own counters
    if (typ == DataManagerType_Thread){
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


// For Testing purposes ONLY
void SetGlobalDriver(AddressStreamDriver* newDriver) {
    Driver = newDriver;
}
