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

#ifndef _CacheSimulation_hpp_
#define _CacheSimulation_hpp_

#include <AddressStreamBase.hpp>
#include <string>
#include <fstream>
#include <unordered_map>

#define DEFAULT_CACHE_FILE "instcode/CacheDescriptions.txt"

#define INVALID_CACHE_LEVEL (0xffffffff)

class CacheStructureHandler;
class CacheStats;
class CacheLevel;
class MainMemory;

enum CacheLevelType {
    CacheLevelType_Undefined,
    CacheLevelType_InclusiveLowassoc,
    CacheLevelType_NonInclusiveLowassoc,
    CacheLevelType_InclusiveHighassoc,
    CacheLevelType_Total
};

enum ReplacementPolicy {
    ReplacementPolicy_Undefined,
    ReplacementPolicy_trulru,
    ReplacementPolicy_nmru,
    ReplacementPolicy_random,
    ReplacementPolicy_direct,
    ReplacementPolicy_Total
};

static const char* ReplacementPolicyNames[ReplacementPolicy_Total] = {
    "undefined",
    "truelru",
    "nmru",
    "random",
    "direct"
};

struct EvictionInfo {
    uint64_t addr;
    uint32_t level;
    uint32_t setid;
    uint32_t lineid;
    bool coldMiss;
    bool dirty;
};

struct LevelStats {
    uint64_t hitCount;
    uint64_t missCount;
    uint64_t loadCount; 
    uint64_t storeCount;
};

class CacheSimulationTool : public AddressStreamTool {
  public:
    CacheSimulationTool() : AddressStreamTool() {}
    virtual void AddNewHandlers(AddressStreamStats* stats);
    virtual void AddNewStreamStats(AddressStreamStats* stats);
    void CacheSimulationFileName(AddressStreamStats* stats, std::string& oFile);
    virtual uint32_t CreateHandlers(uint32_t index, StringParser* parser);
    virtual void FinalizeTool(DataManager<AddressStreamStats*>* AllData,
      SamplingMethod* Sampler);
    void GetAndSetCacheDescriptionFile(StringParser* parser);
    std::string GetCacheDescriptionFileName() { return CacheDescriptionFile; }
    void GetReportFileName(AddressStreamStats* stats, std::string& oFile, 
      std::string suffix);
    uint32_t GetMinimumHighAssociativity() { return MinimumHighAssociativity; }
    virtual void HandleEnvVariables(StringParser* parser);
    bool IsKeepingMemoryLog() { return KeepMemoryLog; }
    bool IsTrackingDirtyStatus() { return TrackDirtyStatus; }
    void MemoryLogFileName(AddressStreamStats* stats, std::string& oFile);
    virtual uint32_t ReadCacheDescription(std::istream& cacheStream, 
      StringParser* parser);

    void SetCacheDescriptionFileName(std::string f) {CacheDescriptionFile = f;}

  protected:
    std::string CacheDescriptionFile = "";
    std::ofstream CacheReportFile;
    uint32_t MinimumHighAssociativity = 256;
    bool KeepMemoryLog = false;
    std::ofstream MemoryLogFile;
    bool TrackDirtyStatus = false;


    virtual void AggregateCacheStats(CacheStats* aggregatedStats, uint32_t 
      aggMemid, CacheStats* cacheStats, uint32_t memid);
    virtual void CloseReportFiles();
    virtual CacheStats* CreateAggregatedCacheStats(CacheStats* stats, uint32_t
      numMemIds);
    virtual void OpenReportFiles(AddressStreamStats* stats);
    void PrintApplicationHeader(std::ofstream& file, 
      DataManager<AddressStreamStats*>* AllData, SamplingMethod* Sampler, 
      uint64_t totalMemop, uint64_t sampledCount);
    virtual void PrintApplicationHeaders(DataManager<AddressStreamStats*>* 
      AllData, SamplingMethod* Sampler, uint64_t totalMemop, uint64_t 
      sampledCount);
    virtual void PrintOverallStatistics(DataManager<AddressStreamStats*>*
      AllData);
    virtual void PrintOverallStatistics(DataManager<AddressStreamStats*>*
      AllData, uint32_t sysidIndex, image_key_t imageid);
    virtual void PrintOverallStatistics(CacheStats* cacheStats, thread_key_t 
      threadid);
    virtual void PrintPerBlockData(DataManager<AddressStreamStats*>* AllData, 
      image_key_t imageid, thread_key_t threadid, CacheStats** aggregatedStats, 
      uint32_t bbid);
    virtual void PrintReportHeaders();
    virtual void PrintSysIdHeader(uint32_t sysid, image_key_t imageid);
    void PrintThreadidInfo(std::ofstream& file, thread_key_t thread, 
      DataManager<AddressStreamStats*>* AllData);
};


class CacheStats : public StreamStats {
public:
    CacheStats(uint32_t lvl, uint32_t sysid, uint32_t capacity, bool
      keepMemoryStats);
    virtual ~CacheStats();

    uint32_t Capacity;
    LevelStats** CacheLevelStats; // indexed by [memid][level]
    bool KeepMemoryStats;
    uint32_t LevelCount;
    MainMemory** MainMemoryStats; // indexed by [memid]
    uint32_t SysId;
 
    void ExtendCapacity(uint32_t newSize);

    uint64_t GetAccessCount(uint32_t memid);
    uint32_t GetCapacity() { return Capacity; }
    float GetCumulativeHitRate(uint32_t memid, uint32_t lvl);
    static float GetHitRate(LevelStats* stats);
    static float GetHitRate(uint64_t hits, uint64_t misses);
    float GetHitRate(uint32_t memid, uint32_t lvl);
    uint64_t GetHits(uint32_t lvl);
    uint64_t GetHits(uint32_t memid, uint32_t lvl);
    LevelStats* GetLevelStats(uint32_t memid, uint32_t lvl);
    uint64_t GetLoads(uint32_t lvl);
    uint64_t GetLoads(uint32_t memid, uint32_t lvl);
    uint64_t GetMisses(uint32_t lvl);
    uint64_t GetMisses(uint32_t memid, uint32_t lvl);
    uint32_t GetNumberOfLevels() { return LevelCount; }
    uint64_t GetStores(uint32_t lvl);
    uint64_t GetStores(uint32_t memid, uint32_t lvl);
    uint32_t GetSysId() { return SysId; }

    bool HasMemId(uint32_t memid);
    void Hit(uint32_t memid, uint32_t lvl);
    void Hit(uint32_t memid, uint32_t lvl, uint32_t cnt);

    void InitMainMemoryStats(CacheStructureHandler* handler);
    bool IsKeepingMemoryStats() { return KeepMemoryStats; }

    void Load(uint32_t memid,uint32_t lvl);
    void Load(uint32_t memid, uint32_t lvl, uint32_t cnt);

    void Miss(uint32_t memid, uint32_t lvl);
    void Miss(uint32_t memid, uint32_t lvl, uint32_t cnt);
   
    void Store(uint32_t memid,uint32_t lvl);
    void Store(uint32_t memid, uint32_t lvl, uint32_t cnt);

    virtual void UpdateLevelStats(uint32_t memid, uint32_t lvl, bool hit, bool 
      load);
    virtual void UpdateMainMemoryStats(uint32_t memid, uint32_t set, uint32_t 
      line, bool load);

    bool Verify();
};

class CacheStructureHandler : public MemoryStreamHandler {
  protected: 

    CacheSimulationTool* CacheSimTool;

    uint32_t AllocatedLevelCount;   // For deleting allocated memory
    uint32_t LevelCount;
    CacheLevel** Levels;
    StringParser* Parser;
    uint32_t SysId;

    virtual void InitializeDataStructures();
    CacheLevel* ParseCacheLevelTokens(std::stringstream& tokenizer, 
      uint32_t levelId, uint32_t* firstExcl);
    virtual bool ParseNonCacheLevelTokens(std::stringstream& tokenizer,
      uint32_t levelId);
    virtual void PostProcessAddress(CacheStats* stats, uint64_t address, 
      uint64_t memseq, uint8_t load, uint32_t currLevel, uint32_t nextLevel,
      EvictionInfo* evictInfo);
    virtual uint32_t ProcessAddress(CacheStats* stats, uint64_t address, 
      uint64_t memseq, uint8_t load);

  public:      
    // note that this doesn't contain any stats gathering code. that is done at
    // the thread level and is therefore done in ThreadData
    CacheStructureHandler(CacheSimulationTool* tool, StringParser* parser);
    CacheStructureHandler(CacheStructureHandler& h);
    virtual ~CacheStructureHandler();

    CacheLevel* GetCacheLevel(uint32_t lvl) { return Levels[lvl]; } //0-indexed
    uint32_t GetMinimumHighAssociativity() { return 
      CacheSimTool->GetMinimumHighAssociativity(); }
    uint32_t GetNumberOfCacheLevels() { return LevelCount; }
    uint32_t GetSysId() { return SysId; }

    virtual bool Init(std::string desc);

    bool IsKeepingMemoryLog() { return CacheSimTool->IsKeepingMemoryLog(); }
    bool IsTrackingDirtyStatus() {return CacheSimTool->IsTrackingDirtyStatus();}

    void Print(std::ofstream& f);
    uint32_t Process(void* stats, BufferEntry* access);
    bool Verify();
};

#define CacheLevel_Init_Interface uint32_t lvl, uint32_t sizeInBytes, uint32_t assoc, uint32_t lineSz, ReplacementPolicy pol, bool trackDirty
#define CacheLevel_Init_Arguments lvl, sizeInBytes, assoc, lineSz, pol, trackDirty

// Keep order of lines (within a set) in a doubly-linked list where:
//   Head is the most recently used
//   Tail is the least recently used
//   Prev is the line accessed less recently than the current line (except tail)
//   Next is the line accessed more recently than the current line (except head)
//   The head and tail are connected as well, instead of pointing to NULL
//
// Let's say 5 lines (A, B, C, D, and E) were accessed in the following order:
//   D, E, B, C, A, D, A
// Then the least recently used is E, then B, then C, then D, then A:
//
//  
//         A -> ----- -> ----- -> ----- -> ----- -> ----- -> E      (next)
// LRU (T)      | E |    | B |    | C |    | D |    | A |      (H)  MRU
//         A <- ----- <- ----- <- ----- <- ----- <- ----- <- E      (prev)
//
//
// Note: in CacheLevel, we keep track of the LRU in the "RecentlyUsed" data 
//       structure. In HistoryUsed, we just keep track of which line is 
//       next/previous to the given line
struct history {
    uint32_t prev;
    uint32_t next;
};

class CacheLevel {
protected:

    // Description of cache level
    uint32_t Level;               // current level #
    uint32_t LevelCount;          // # levels
    uint32_t Size;                // size of cache
    uint32_t Associativity;       // # of lines per set
    uint32_t LineSize;            // # bytes in a cache line
    ReplacementPolicy ReplPolicy; // replacement policy
    CacheLevelType Type;          // type (e.g. inclusive)

    // Cache Level metadata
    uint32_t NumBitsUsedPerLine;     // Number of bits used in a cache line
    uint32_t NumSets;                // Number of sets
    Randomizer* RanPolicyRandomizer; // Randomizer for random policy
	  bool TrackDirtyStatus;           // Are we tracking dirty lines

    // Cache Level data structures
    uint64_t** Contents = nullptr;    // the cache -> Contents[setid][lineid]
    bool**  DirtyStatus = nullptr;    // is Contents[setid][lineid] dirty?
    history** HistoryUsed = nullptr;  // doubly-linked list for each set
    uint32_t* RecentlyUsed = nullptr; // MRU for lru (nmru) and LRU for trulru

    // Is the cache line at this set and line dirty?
    virtual bool GetDirtyStatus(uint32_t setid, uint32_t lineid);
    // Get set for a given cache address
    uint32_t GetSet(uint64_t cacheAddress);
    // Get the line to replace for a given set (as given by replacment policy)
    uint32_t LineToReplace(uint32_t setid);
    // Mark the Contents[setid][lineid] as just used
    void MarkUsed(uint32_t setid, uint32_t lineid);
    // Add the new cache address to the cache and return the replaced address
    virtual uint64_t Replace(uint64_t cacheAddress, uint32_t setid, 
      uint32_t lineid);
    // Reset Dirty bit for the given set and line
    virtual void ResetDirty(uint32_t setid, uint32_t lineid);
    // Look for the given cache address in the cache and return the set/line
    virtual bool Search(uint64_t addr, uint32_t* set, uint32_t* lineInSet);
    // Set the dirty bit for the given set and line
    virtual void SetDirty(uint32_t setid, uint32_t lineid);

    // Return the type for the cache level
    virtual const char* TypeString() = 0;

public:
    CacheLevel();
    virtual ~CacheLevel();

    // For extracting level arguments
    virtual uint32_t GetAssociativity() { return Associativity; }
    virtual bool GetIsTrackingDirty() { return TrackDirtyStatus; }
    virtual uint32_t GetLevel() { return Level; }
    virtual uint32_t GetLineSize() { return LineSize; }
    ReplacementPolicy GetReplacementPolicy() { return ReplPolicy; }
    virtual uint32_t GetSizeInBytes() { return Size; }
    virtual CacheLevelType GetType() { return Type; }

    // Get the cache address, the first address in a cache line
    uint64_t GetCacheAddress(uint64_t addr);
    virtual uint32_t GetSetCount() { return NumSets; }
    // Initialize this cache level
    virtual void Init(CacheLevel_Init_Interface);
    // Print a description of the cache level
    void Print(std::ofstream& f, uint32_t sysid);
    void SetLevelCount(uint32_t num) { LevelCount = num; }
    // Process the given address
    virtual uint32_t Process(uint64_t addr, uint64_t loadstoreflag, 
      EvictionInfo* info);

    // For testing purposes
    uint64_t** GetContents() { return Contents; }
    bool** GetDirtyStatus() { return DirtyStatus; }
    uint32_t GetLevelCount() { return LevelCount; }
    uint32_t GetNumBitsUsedPerLine() { return NumBitsUsedPerLine; }
    history** GetHistoryUsed() { return HistoryUsed; }
    uint32_t* GetRecentlyUsed() { return RecentlyUsed; }

};

class InclusiveCacheLevel : public virtual CacheLevel {
public:
    InclusiveCacheLevel() {}
    ~InclusiveCacheLevel() {}

    virtual void Init(CacheLevel_Init_Interface) {
        CacheLevel::Init(CacheLevel_Init_Arguments);
        Type = CacheLevelType_InclusiveLowassoc;
    }
    virtual const char* TypeString() { return "inclusive"; }
};

class NonInclusiveCacheLevel : public virtual CacheLevel {
public:
    uint32_t FirstExclusive;
    uint32_t LastExclusive;

    NonInclusiveCacheLevel() {}
    virtual void Init(CacheLevel_Init_Interface) {
        CacheLevel::Init(CacheLevel_Init_Arguments);
        Type = CacheLevelType_NonInclusiveLowassoc;
    }
    virtual uint32_t Process(uint64_t addr, uint64_t loadstoreflag, 
      EvictionInfo* info);
    virtual const char* TypeString() { return "noninclusive"; }
};

// Should used in conjunction with another cache level 
// (see HighlyAssociativeInclusiveCacheLevel)
class HighlyAssociativeCacheLevel : public virtual CacheLevel {
protected:
    std::unordered_map<uint64_t, uint32_t>** FastContents;

    uint64_t Replace(uint64_t cacheAddress, uint32_t setid, uint32_t lineid);
    bool Search(uint64_t cacheAddress, uint32_t* set, uint32_t* lineInSet);

public:
    HighlyAssociativeCacheLevel() : FastContents(NULL) {}
    ~HighlyAssociativeCacheLevel();

    virtual void Init(CacheLevel_Init_Interface);
};

class HighlyAssociativeInclusiveCacheLevel : public InclusiveCacheLevel, 
  public HighlyAssociativeCacheLevel {
public:
    HighlyAssociativeInclusiveCacheLevel() {}
    virtual void Init(CacheLevel_Init_Interface) {
        InclusiveCacheLevel::Init(CacheLevel_Init_Arguments);
        HighlyAssociativeCacheLevel::Init(CacheLevel_Init_Arguments);
        Type = CacheLevelType_InclusiveHighassoc;
    }
    const char* TypeString() { return "inclusive_H"; }
};

class MainMemory {
public:
    MainMemory(uint32_t setSize, uint32_t numOfLines, uint32_t lineSize); 
    MainMemory(MainMemory& mem);
    ~MainMemory();

    //Below HashMaps are used to keep count of loads and store to and from main memory
    NestedHash* writeOutsMap = nullptr; //keyed by set and line
    NestedHash* readInsMap = nullptr; //keyed by set and line

    EasyHash* dirOutsMap = nullptr; //if using a direct map last level cache,
    EasyHash* dirInsMap = nullptr; //should hopefully cut down even more memory usage

    uint32_t GetLoads(); //loops through all of readIns and gets a total sum
    uint32_t GetStores(); //loops through all of writeOuts and gets a total sum

    uint32_t numOfSets; //based on Last Level Cache
    uint32_t numOfLinesInSet;
    uint32_t sizeOfLine;
};


#endif /* _CacheSimulation_hpp_ */
