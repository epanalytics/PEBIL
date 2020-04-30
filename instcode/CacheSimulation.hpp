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
    std::string GetCacheDescriptionFileName() { return CacheDescriptionFile; }
    void GetAndSetCacheDescriptionFile(StringParser* parser);
    uint32_t GetMinimumHighAssociativity() { return MinimumHighAssociativity; }
    virtual void HandleEnvVariables(StringParser* parser);
    bool IsKeepingMemoryLog() { return KeepMemoryLog; }
    bool IsTrackingDirtyStatus() { return TrackDirtyStatus; }
    void LogFileName(AddressStreamStats* stats, std::string& oFile);
    virtual uint32_t ReadCacheDescription(std::istream& cacheStream, 
      StringParser* parser);

    void SetCacheDescriptionFileName(std::string f) {CacheDescriptionFile = f;}

  protected:
    std::string CacheDescriptionFile;
    uint32_t MinimumHighAssociativity = 256;
    bool KeepMemoryLog = false;
    bool TrackDirtyStatus = false;

    void PrintApplicationHeader(std::ofstream& file, 
      DataManager<AddressStreamStats*>* AllData, SamplingMethod* Sampler, 
      uint64_t totalMemop, uint64_t sampledCount);
    void PrintPerBlockCacheSimData(std::ofstream& file,
      DataManager<AddressStreamStats*>* AllData);
    void PrintSysidInfo(std::ofstream& file, CacheStats* c, std::set<image_key_t>::iterator iit);
    void PrintThreadidInfo(std::ofstream& file, thread_key_t thread, 
      DataManager<AddressStreamStats*>* AllData);
};


class CacheStats : public StreamStats {
public:
    uint32_t LevelCount;
    uint32_t SysId;
    LevelStats** levelStats; // indexed by [memid][level]
    MainMemory** mainMemoryStats; // indexed by [memid]
    uint32_t Capacity;
    CacheStats(uint32_t lvl, uint32_t sysid, uint32_t capacity, uint32_t 
      hybridCache);
    ~CacheStats();
    void InitMainMemoryStats(CacheStructureHandler* handler);

    bool HasMemId(uint32_t memid);
    void ExtendCapacity(uint32_t newSize);
    void NewMem(uint32_t memid);

    void Hit(uint32_t memid, uint32_t lvl);

    void Miss(uint32_t memid, uint32_t lvl);

    void Hit(uint32_t memid, uint32_t lvl, uint32_t cnt);

    void Miss(uint32_t memid, uint32_t lvl, uint32_t cnt);

    void Load(uint32_t memid,uint32_t lvl);
    void Load(uint32_t memid, uint32_t lvl, uint32_t cnt);
   
    void Store(uint32_t memid,uint32_t lvl);
    void Store(uint32_t memid, uint32_t lvl, uint32_t cnt);
 
    uint64_t GetLoads(uint32_t memid, uint32_t lvl);
    uint64_t GetLoads(uint32_t lvl);
    
    uint64_t GetStores(uint32_t memid, uint32_t lvl);
    uint64_t GetStores(uint32_t lvl);    

    static float GetHitRate(LevelStats* stats);
    static float GetHitRate(uint64_t hits, uint64_t misses);

    uint64_t GetHits(uint32_t memid, uint32_t lvl);

    uint64_t GetHits(uint32_t lvl);
    
    uint64_t GetMisses(uint32_t memid, uint32_t lvl);

    uint64_t GetMisses(uint32_t lvl);

    LevelStats* GetLevelStats(uint32_t memid, uint32_t lvl);
    uint64_t GetAccessCount(uint32_t memid);
    float GetHitRate(uint32_t memid, uint32_t lvl);
    float GetCumulativeHitRate(uint32_t memid, uint32_t lvl);

    void UpdateLevelStats(uint32_t memid, uint32_t lvl, bool hit, bool load);
    void UpdateMainMemoryStats(uint32_t memid, uint32_t set, uint32_t line, 
      bool load);

    bool Verify();
};

class CacheStructureHandler : public MemoryStreamHandler {
  protected: 

    CacheSimulationTool* cacheSimTool;

    uint32_t sysId;
    uint32_t levelCount;

    CacheLevel** levels;
    //std::string description;

//    uint32_t MinimumHighAssociativity = 256;
//    uint32_t DirtyCacheHandling = 0;

    bool isInitialized = false;

    uint64_t hits;
    uint64_t misses;
    //uint64_t AddressRangesCount;
    StringParser* parser;
    std::vector<uint64_t>* toEvictAddresses;
    uint32_t processAddress(void* stats, uint64_t address, uint64_t memseq, 
      uint8_t loadstoreflag);

  public:      
    // note that this doesn't contain any stats gathering code. that is done at
    // the thread level and is therefore done in ThreadData

    CacheStructureHandler(CacheSimulationTool* cacheSimTool);
    CacheStructureHandler(CacheStructureHandler& h);
    ~CacheStructureHandler();
    virtual bool Init(std::string desc);

    CacheLevel* GetCacheLevel(uint32_t lvl) { return levels[lvl]; } //0-indexed
    uint32_t GetMinimumHighAssociativity() { return 
      cacheSimTool->GetMinimumHighAssociativity(); }
    uint32_t GetNumberOfCacheLevels() { return levelCount; }
    uint32_t GetSysId() { return sysId; }

    bool IsInitialized() { return isInitialized; }
    bool IsKeepingMemoryLog() { return cacheSimTool->IsKeepingMemoryLog(); }
    bool IsTrackingDirtyStatus() {return cacheSimTool->IsTrackingDirtyStatus();}

    CacheLevel* ParseCacheLevelTokens(std::stringstream& tokenizer, 
      uint32_t levelId, uint32_t* firstExcl);
    void Print(std::ofstream& f);
    uint32_t Process(void* stats, BufferEntry* access);
    void SetParser(StringParser* p) { parser = p; }
    bool Verify();

    uint64_t GetHits(){return hits;}
    uint64_t GetMisses(){ return misses;} 

    //bool CheckRange(CacheStats* stats,uint64_t addr,uint64_t loadstoreflag,uint32_t memid); //, uint32_t* set, uint32_t* lineInSet);    
    //void ExtractAddresses();

    /* For testing only */
    void SetCacheLevel(uint32_t lvl, CacheLevel* c) { levels[lvl] = c; }
    void SetNumberOfCacheLevels(uint32_t n) { levelCount = n; }
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

    // Get the cache address, the first address in a cache line
    uint64_t GetCacheAddress(uint64_t addr);
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
    
    // uint64_t GetAddress(uint64_t store);
    //bool MultipleLines(uint64_t addr, uint32_t width);

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


    //virtual uint32_t EvictProcess(CacheStats* stats, uint32_t memid, uint64_t 
    //  addr, uint64_t loadstoreflag, void* info);    

 //   std::vector<uint64_t>* toEvictAddresses = nullptr;
//    virtual void EvictDirty(CacheStats* stats, CacheLevel** Levels, uint32_t 
//      memid, void* info); // void* info is needed since eventually 'Process' 
      // needs to be called! 
//    virtual bool IsExclusive() { return false; }

    //std::vector<uint64_t>* passEvictAddresses() { return toEvictAddresses;}
};

class InclusiveCacheLevel : public virtual CacheLevel {
public:
    InclusiveCacheLevel() {}
    ~InclusiveCacheLevel() {}

    virtual void Init(CacheLevel_Init_Interface) {
        CacheLevel::Init(CacheLevel_Init_Arguments);
        Type = CacheLevelType_InclusiveLowassoc;
    }
    bool IsExclusive() { return false; }
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
    bool IsExclusive() { return false; }
    virtual uint32_t Process(uint64_t addr, uint64_t loadstoreflag, 
      EvictionInfo* info);
    virtual const char* TypeString() { return "exclusive"; }
};

class HighlyAssociativeCacheLevel : public virtual CacheLevel {
protected:
    pebil_map_type <uint64_t, uint32_t>** fastcontents;
    pebil_map_type <uint64_t, bool>** fastcontentsdirty;
public:
    HighlyAssociativeCacheLevel() {}
    ~HighlyAssociativeCacheLevel();

    bool Search(uint64_t addr, uint32_t* set, uint32_t* lineInSet);
    uint64_t Replace(uint64_t addr, uint32_t setid, uint32_t lineid);
    virtual void Init(CacheLevel_Init_Interface);

   // Both store and lineid is being sent since while calling these methods we do not make distinction as whether the object belongs to CacheLevel or HighlyAssociateCacheLevel
   void SetDirty(uint32_t setid, uint32_t lineid);
   void ResetDirty(uint32_t setid, uint32_t lineid);
//   bool GetDirtyStatus(uint32_t setid, uint32_t lineid,uint64_t store);  
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
