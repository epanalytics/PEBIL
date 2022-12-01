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

#ifdef HAS_DATA_STRUCTURE_MODULE
class DataStructureModule;
#endif

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
    bool runSpatialLocalityPerMemOp;

    // Which tool versions are we running?
    bool runCodeCentric;
    bool runDataCentric;

    // Holds the tools that are being run
    // First tools are code centric. Data centric will be after.
    std::vector<AddressStreamTool*>* tools = NULL;
    uint32_t numCodeCentricTools;

    // Code Centric Handlers will be first. Then the Data Centric Handlers.
    uint32_t numMemoryHandlers;
    uint32_t numCodeCentricMemoryHandlers;

    // Used for passing addresses from vectorized instruction to the tools
    // TODO make thread safe when merging with DataCentric
    uint64_t maxNumAddresses;
    uint64_t* addresses = NULL;


    DynamicInstrumentation* dynamicPoints = NULL;
    SamplingMethod* sampler = NULL;
    DataManager<AddressStreamStats*>* allData = NULL;
    FastData<AddressStreamStats*, BufferEntry*>* fastData = NULL;
    // set of instrumentation points that add addresses to the buffer
    std::set<uint64_t>* liveMemoryAccessInstPointKeys = NULL;  

    StringParser* parser = NULL;

    std::string variableNameFile; // For data structure module

  #ifdef HAS_DATA_STRUCTURE_MODULE
    DataStructureModule* dataStructureModule = NULL;
  #else
    int dataStructureModule = 0;  // placeholder to make .cpp code cleaner
  #endif
  public:
    AddressStreamDriver();
    virtual ~AddressStreamDriver();

    bool BuiltWithDataStructureModule();
    bool BuiltWithEPATools();

    void CreateFastData(uint64_t capacity);
    virtual void CreateSamplingMethod();

    void DeleteAllData();

    bool EnterTool();
    void ExitTool(bool needToExit);

    void* FinalizeImage(image_key_t*);

    DataManager<AddressStreamStats*>* GetAllData() { return allData; }
    void GetAndSetVariableNameFile();
    DynamicInstrumentation* GetDynamicPoints() { return dynamicPoints; }
    FastData<AddressStreamStats*, BufferEntry*>* GetFastData() { 
      return fastData; }
    std::set<uint64_t>* GetLiveInstKeys() { return 
      liveMemoryAccessInstPointKeys; }
    SamplingMethod* GetSamplingMethod() { return sampler; }
    StringParser* GetStringParser() { return parser; }
    std::string GetVariableNameFile() { return variableNameFile; }

    uint32_t GetNumCodeCentricTools() { return numCodeCentricTools; }
    uint32_t GetNumCodeCentricMemoryHandlers() { return 
      numCodeCentricMemoryHandlers; }
    uint32_t GetNumMemoryHandlers() { return numMemoryHandlers; }
    uint32_t GetNumTools() { return tools->size(); }

    bool HasLiveInstrumentationPoints(bool lock=true);

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
    bool IsSpatialLocalityPerMemOp() { return runSpatialLocalityPerMemOp; }

    bool IsCodeCentric() { return runCodeCentric; }
    bool IsDataCentric() { return runDataCentric; }

    void PauseApplicationWrappers();
    void ProcessAllBuffers();
    uint64_t ProcessBufferForEachHandler(image_key_t iid, thread_key_t tid, 
      uint32_t numElementsInBuffer, bool lock);
    void* ProcessThreadBuffer(image_key_t iid, thread_key_t tid, bool suspend=
      true);

    void SetFastData(FastData<AddressStreamStats*, BufferEntry*>* f) { 
      fastData = f; }
    void SetDynamicPoints(DynamicInstrumentation* d) { dynamicPoints = d; }
    void SetDynamicPoints(bool on);

    virtual void SetUpDataStructureModule();
    virtual void SetUpTools();

    void ShutOffInstrumentationInAllBlocks();
    void ShutOffInstrumentationInBlock(uint64_t blockID, uint64_t imageSeq);
    void ShutOffInstrumentationInBlocks(std::set<uint64_t>& blocks, image_key_t 
      iid, bool suspend = true);
    void ShutOffInstrumentationInMaxedGroups(image_key_t, thread_key_t, bool
      suspend=true);

    void ReadLockDSM(bool lock=true);
    void RegisterThreadInDynamicTool();
    void UnpauseApplicationWrappers();
    void UnLockDSM(bool lock=true);
    void WriteLockDSM(bool lock=true);

    // For Testing Purposes
    void AddTool(AddressStreamTool* t) { tools->push_back(t); }
    AddressStreamTool* GetTool(uint32_t index);
    void SetAddressRange(bool b) { runAddressRange = b; }
    void SetCacheSimulation(bool b) { runCacheSimulation = b; }
    void SetHardwarePrefetching(bool b) { runHardwarePrefetching = b; }
    void SetReuseDistance(bool b) { runReuseDistance = b; }
    void SetScatterLength(bool b) { runScatterLength = b; }
    void SetSpatialLocality(bool b) { runSpatialLocality = b; }

    void SetCodeCentric(bool b) { runCodeCentric = b; }
    void SetDataCentric(bool b) { runDataCentric = b; }

    void SetNumMemoryHandlers(uint32_t n) { numMemoryHandlers = n; }
    void SetNumCodeCentricMemoryHandlers(uint32_t n) { 
      numCodeCentricMemoryHandlers = n; }
    void SetParser(StringParser* p);
    void SetSampler(SamplingMethod* s);
};

void GetBufferIds(BufferEntry* b, image_key_t* i);


#endif /* _AddressStreamDriver_cpp_ */

