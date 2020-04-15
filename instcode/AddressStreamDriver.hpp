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

class DynamicInstrumentation;
class MemoryStreamHandler;
class SamplingMethod;
class AddressRangeTool;
class CacheSimulationTool;
class ReuseDistanceTool;
class ScatterGatherLengthTool;
class SpatialLocalityTool;
template <class T> class DataManager;
template <class T, class V> class FastData;
typedef struct AddressStreamStats_s AddressStreamStats;
typedef struct BufferEntry_s BufferEntry;

#define DEFAULT_SAMPLE_ON  1000000
#define DEFAULT_SAMPLE_OFF 10000000
#define DEFAULT_SAMPLE_MAX 0

// Class to hold important variables and functions together
class AddressStreamDriver {
  private:
  
    // Are we running these tools?
    bool runAddressRange;
    bool runCacheSimulation;
    bool runHardwarePrefetching;
    bool runReuseDistance;
    bool runScatterLength;
    bool runSpatialLocality;

    // Holds the tools that are being run
    std::vector<AddressStreamTool*>* tools = NULL;

    uint32_t numMemoryHandlers;

    DynamicInstrumentation* dynamicPoints = NULL;
    SamplingMethod* sampler = NULL;
    DataManager<AddressStreamStats*>* allData = NULL;
    FastData<AddressStreamStats*, BufferEntry*>* fastData = NULL;
    // set of instrumentation points that add addresses to the buffer
    std::set<uint64_t>* liveMemoryAccessInstPointKeys = NULL;  

    StringParser* parser = NULL;
  public:
    AddressStreamDriver();
    virtual ~AddressStreamDriver();

    void CreateFastData(uint64_t capacity);
    virtual void CreateSamplingMethod();

    void DeleteAllData();

    void* FinalizeImage(image_key_t*);

    DataManager<AddressStreamStats*>* GetAllData() { return allData; }
    DynamicInstrumentation* GetDynamicPoints() { return dynamicPoints; }
    FastData<AddressStreamStats*, BufferEntry*>* GetFastData() { 
      return fastData; }
    std::set<uint64_t>* GetLiveInstKeys() { return 
      liveMemoryAccessInstPointKeys; }
    SamplingMethod* GetSamplingMethod() { return sampler; }
    StringParser* GetStringParser() { return parser; }

    uint32_t GetNumMemoryHandlers() { return numMemoryHandlers; }
    uint32_t GetNumTools() { return tools->size(); }
    AddressStreamTool* GetTool(uint32_t index);

    bool HasLiveInstrumentationPoints();

    void InitializeAddressStreamDriver(DataManager<AddressStreamStats*>* d);
    void InitializeKeys();
    void* InitializeNewImage(image_key_t* iid, AddressStreamStats* stats, 
      ThreadData* threadData);
    void* InitializeNewThread(thread_key_t tid);
    virtual void InitializeStatsWithNewHandlers(AddressStreamStats* stats);
    virtual void InitializeStatsWithNewStreamStats(AddressStreamStats* stats);

    bool IsAddressRange() { return runAddressRange; }
    bool IsCacheSimulation() { return runCacheSimulation; }
    bool IsHardwarePrefetching() { return runHardwarePrefetching; }
    bool IsReuseDistance() { return runReuseDistance; }
    bool IsScatterLength() { return runScatterLength; }
    bool IsSpatialLocality() { return runSpatialLocality; }

    void ProcessBufferForEachHandler(image_key_t iid, thread_key_t tid, 
      uint32_t numElementsInBuffer);
    void* ProcessThreadBuffer(image_key_t iid, thread_key_t tid);

    void SetFastData(FastData<AddressStreamStats*, BufferEntry*>* f) { 
      fastData = f; }
    void SetDynamicPoints(DynamicInstrumentation* d) { dynamicPoints = d; }

    virtual void SetUpTools();

    void ShutOffInstrumentationInAllBlocks();
    void ShutOffInstrumentationInBlock(uint32_t blockID);
    void ShutOffInstrumentationInBlocks(std::set<uint32_t>& blocks);
    void ShutOffInstrumentationInMaxedGroups(image_key_t, thread_key_t);

    // For Testing Purposes
    void AddTool(AddressStreamTool* t) { tools->push_back(t); }
    void SetAddressRange(bool b) { runAddressRange = b; }
    void SetCacheSimulation(bool b) { runCacheSimulation = b; }
    void SetHardwarePrefetching(bool b) { runHardwarePrefetching = b; }
    void SetReuseDistance(bool b) { runReuseDistance = b; }
    void SetScatterLength(bool b) { runScatterLength = b; }
    void SetSpatialLocality(bool b) { runSpatialLocality = b; }

    void SetNumMemoryHandlers(uint32_t n) { numMemoryHandlers = n; }
    void SetParser(StringParser* p);
    void SetSampler(SamplingMethod* s);
};

void GetBufferIds(BufferEntry* b, image_key_t* i);


#endif /* _AddressStreamDriver_cpp_ */

