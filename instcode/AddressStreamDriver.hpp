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

#ifndef _AddressStreamDriver_hpp_
#define _AddressStreamDriver_hpp_

#include <set>
#include <cstdint>

class MemoryStreamHandler;
class SamplingMethod;
template <class T> class DataManager;
template <class T, class V> class FastData;
typedef struct AddressStreamStats_s AddressStreamStats;
typedef struct BufferEntry_s BufferEntry;

// Class to hold important variables and functions together
class AddressStreamDriver {
  private:

    // Are we running these bools?
    bool runAddressRange;
    bool runCacheSimulation;
    bool runReuseDistance;
    bool runScatterLength;
    bool runSpatialLocality;

    // Holds a copy of the memory handlers
    // This is for creating MemoryHandlers in the AddressStreamStats structure
    // Otherwise, do not use them to process data!
    std::vector<MemoryStreamHandler*>* tempMemoryHandlers = NULL;

    // Memory and Reuse handlers -- how many
    uint32_t numReuseHandlers;

    // Memory and Reuse handlers -- which tool owns which handler
    int32_t addressRangeIndex;
    int32_t cacheSimulationFirstIndex;
    int32_t cacheSimulationLastIndex; // Exclusive
    int32_t reuseDistanceIndex;
    int32_t scatterLengthIndex;
    int32_t spatialLocalityIndex;

    SamplingMethod* sampler = NULL;
    DataManager<AddressStreamStats*>* allData = NULL;
    FastData<AddressStreamStats*, BufferEntry*>* fastData = NULL;
    std::set<uint64_t>* liveInstPointKeys = NULL;  // set of keys of active 
                                                   // inst points

    // Tool-specific data
    // Reuse Distance
    uint32_t reuseWindow;
    uint32_t reuseBin;

    // Spatial Locality
    uint32_t spatialWindow;
    uint32_t spatialBin;
    uint32_t spatialNMAX;
  public:
    AddressStreamDriver();
    virtual ~AddressStreamDriver();

    void CreateFastData(uint64_t capacity);
    virtual void CreateSamplingMethod();

    void DeleteAllData();

    DataManager<AddressStreamStats*>* GetAllData() { return allData; }
    FastData<AddressStreamStats*, BufferEntry*>* GetFastData() { 
      return fastData; }
    SamplingMethod* GetSamplingMethod() { return sampler; }

    uint32_t GetNumMemoryHandlers() { return tempMemoryHandlers->size(); }
    uint32_t GetNumReuseHandlers() { return numReuseHandlers; }

    bool HasLiveInstrumentationPoints();

    void* FinalizeImage(image_key_t*);

    void InitializeAddressStreamDriver(DataManager<AddressStreamStats*>* d);
    void InitializeKeys();
    void* InitializeNewImage(image_key_t* iid, AddressStreamStats* stats, 
      ThreadData* threadData);
    void* InitializeNewThread(thread_key_t tid);
    void InitializeStatsWithNewHandlers(AddressStreamStats* stats);
    void InitializeStatsWithNewStreamStats(AddressStreamStats* stats);

    bool IsAddressRange() { return runAddressRange; }
    bool IsCacheSimulation() { return runCacheSimulation; }
    bool IsReuseDistance() { return runReuseDistance; }
    bool IsScatterLength() { return runScatterLength; }
    bool IsSpatialLocality() { return runSpatialLocality; }

    void ProcessMemoryBuffer(image_key_t iid, thread_key_t tid, 
      MemoryStreamHandler* handler, uint32_t handlerIndex, uint32_t
      numElementsInBuffer);
    void ProcessReuseBuffer(image_key_t iid, thread_key_t tid,
      ReuseDistance* rd, uint32_t numElements);
    void* ProcessThreadBuffer(image_key_t iid, thread_key_t tid);

    void SetAllData(DataManager<AddressStreamStats*>* d) { allData = d; }
    void SetFastData(FastData<AddressStreamStats*, BufferEntry*>* f) { 
      fastData = f; }

    void SetAddressRange(bool b) { runAddressRange = b; }
    void SetCacheSimulation(bool b) { runCacheSimulation = b; }
    void SetReuseDistance(bool b) { runReuseDistance = b; }
    void SetScatterLength(bool b) { runScatterLength = b; }
    void SetSpatialLocality(bool b) { runSpatialLocality = b; }

    virtual void SetUpLibraries();

};

void GetBufferIds(BufferEntry* b, image_key_t* i);


#endif /* _AddressStreamDriver_cpp_ */

