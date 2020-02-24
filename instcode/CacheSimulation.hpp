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

enum CacheLevelType {
    CacheLevelType_Undefined,
    CacheLevelType_InclusiveLowassoc,
    CacheLevelType_ExclusiveLowassoc,
    CacheLevelType_NonInclusiveLowassoc,
    CacheLevelType_InclusiveHighassoc,
    CacheLevelType_ExclusiveHighassoc,
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
};

struct LevelStats {
    uint64_t hitCount;
    uint64_t missCount;
    uint64_t loadCount; 
    uint64_t storeCount;
};

class MainMemory {
public:
    MainMemory(uint32_t setSize, uint32_t numOfLines, uint32_t lineSize); 
    MainMemory(MainMemory& mem);
    ~MainMemory();

    uint32_t** writeOuts; //2d array indexed by set and lineInSet
    uint32_t** readIns; //2d array indexed by set and lineInSet

    uint32_t GetLoads(); //loops through all of readIns and gets a total sum
    uint32_t GetStores(); //loops through all of writeOuts and gets a total sum

    uint32_t numOfSets; //based on Last Level Cache
    uint32_t numOfLinesInSet;
    uint32_t sizeOfLine;
};

class CacheSimulationTool : public AddressStreamTool {
  public:
    CacheSimulationTool() : AddressStreamTool() {}
    virtual void AddNewHandlers(AddressStreamStats* stats);
    virtual void AddNewStreamStats(AddressStreamStats* stats);
    virtual uint32_t CreateHandlers(uint32_t index, StringParser* parser);
    virtual void FinalizeTool(DataManager<AddressStreamStats*>* AllData,
      SamplingMethod* Sampler);
    void CacheSimulationFileName(AddressStreamStats* stats, std::string& oFile);
    void LogFileName(AddressStreamStats* stats, std::string& oFile);

    std::string GetCacheDescriptionFile(StringParser* parser);
    const char* HandleEnvVariables(uint32_t index, StringParser* parser, 
      std::string& cachedf);
    uint32_t ReadCacheDescription(std::istream& stream, StringParser* parser,
      std::string& cachedf);

  protected:
    uint32_t MinimumHighAssociativity = 256;
    uint32_t LoadStoreLogging = 0;
    uint32_t DirtyCacheHandling = 0;
    void PrintApplicationHeader(std::ofstream& file, 
      DataManager<AddressStreamStats*>* AllData, SamplingMethod* Sampler, 
      uint64_t totalMemop, uint64_t sampledCount);
    void PrintSysidInfo(std::ofstream& file, CacheStats* c, std::set<image_key_t>::iterator iit);
};


class CacheStats : public StreamStats {
public:
    uint32_t LevelCount;
    uint32_t SysId;
    LevelStats** Stats; // indexed by [memid][level]
    LevelStats* HybridMemStats; // indexed by [memid]
    MainMemory** mainMemoryStats; // indexed by [memid]
    uint32_t Capacity;
    uint32_t hybridCache;
    CacheStats(uint32_t lvl, uint32_t sysid, uint32_t capacity, uint32_t 
      hybridCache);
    ~CacheStats();
    void InitMainMemoryStats(CacheStructureHandler* handler);

    bool HasMemId(uint32_t memid);
    void ExtendCapacity(uint32_t newSize);
    void NewMem(uint32_t memid);

    void Hit(uint32_t memid, uint32_t lvl);
    void HybridHit(uint32_t memid);

    void Miss(uint32_t memid, uint32_t lvl);
    void HybridMiss(uint32_t memid);

    void Hit(uint32_t memid, uint32_t lvl, uint32_t cnt);
    void HybridHit(uint32_t memid, uint32_t cnt);

    void Miss(uint32_t memid, uint32_t lvl, uint32_t cnt);
    void HybridMiss(uint32_t memid,uint32_t cnt);

    void Load(uint32_t memid,uint32_t lvl);
    void Load(uint32_t memid, uint32_t lvl, uint32_t cnt);
    void HybridLoad(uint32_t memid);
    void HybridLoad(uint32_t memid,uint32_t cnt); //  void HybridLoads(uint32_t memid, uint32_t cnt);
   
    void Store(uint32_t memid,uint32_t lvl);
    void Store(uint32_t memid, uint32_t lvl, uint32_t cnt);
    void HybridStore(uint32_t memid);
    void HybridStore(uint32_t memid,uint32_t cnt);//    void HybridStores(uint32_t memid, uint32_t cnt);
 
    uint64_t GetLoads(uint32_t memid, uint32_t lvl);
    uint64_t GetLoads(uint32_t lvl);
    uint64_t GetHybridLoads(uint32_t memid);
    uint64_t GetHybridLoads();
    
    uint64_t GetStores(uint32_t memid, uint32_t lvl);
    uint64_t GetStores(uint32_t lvl);    
    uint64_t GetHybridStores(uint32_t memid);
    uint64_t GetHybridStores();    

    static float GetHitRate(LevelStats* stats);
    static float GetHitRate(uint64_t hits, uint64_t misses);

    uint64_t GetHits(uint32_t memid, uint32_t lvl);
    uint64_t GetHybridHits(uint32_t memid);

    uint64_t GetHits(uint32_t lvl);
    uint64_t GetHybridHits();
    
    uint64_t GetMisses(uint32_t memid, uint32_t lvl);
    uint64_t GetHybridMisses(uint32_t memid);

    uint64_t GetMisses(uint32_t lvl);
    uint64_t GetHybridMisses();

    LevelStats* GetLevelStats(uint32_t memid, uint32_t lvl);
    uint64_t GetAccessCount(uint32_t memid);
    float GetHitRate(uint32_t memid, uint32_t lvl);
    float GetCumulativeHitRate(uint32_t memid, uint32_t lvl);

    bool Verify();
};

#define USES_MARKERS(__pol) (__pol == ReplacementPolicy_nmru)
#define CacheLevel_Init_Interface uint32_t lvl, uint32_t sizeInBytes, uint32_t assoc, uint32_t lineSz, ReplacementPolicy pol, uint32_t loadStore, uint32_t dirtyCache
#define CacheLevel_Init_Arguments lvl, sizeInBytes, assoc, lineSz, pol, loadStore, dirtyCache

struct history {
    uint32_t prev;
    uint32_t next;
};

class CacheLevel {
protected:

    CacheLevelType type;

    uint32_t level;
    uint32_t levelCount;
    uint32_t size;
    uint32_t associativity;
    uint32_t linesize;
    ReplacementPolicy replpolicy;

    uint32_t countsets;
    uint32_t linesizeBits;

    uint64_t** contents = nullptr;
    bool**  dirtystatus = nullptr;
    uint32_t* recentlyUsed = nullptr;
    history** historyUsed = nullptr;
    bool toEvict;

	uint32_t loadStoreLogging;
	uint32_t dirtyCacheHandling;

public:
    std::vector<uint64_t>* toEvictAddresses = nullptr;
    CacheLevel();
    virtual ~CacheLevel();

    bool IsExclusive() { return (type == CacheLevelType_ExclusiveLowassoc || 
      type == CacheLevelType_ExclusiveHighassoc); }

    uint32_t GetLevelCount() { return levelCount;}
    uint32_t SetLevelCount(uint32_t inpLevelCount) { return levelCount = 
      inpLevelCount; }
    virtual CacheLevelType GetType() { return type; }
    ReplacementPolicy GetReplacementPolicy() { return replpolicy; }
    virtual uint32_t GetLevel() { return level; }
    virtual uint32_t GetSizeInBytes() { return size; }
    virtual uint32_t GetAssociativity() { return associativity; }
    virtual uint32_t GetSetCount() { return countsets; }
    virtual uint32_t GetLineSize() { return linesize; }
	virtual uint32_t GetLoadStoreLog() { return loadStoreLogging; }
	virtual uint32_t GetDirtyCacheHandle() { return dirtyCacheHandling; }
    uint64_t CountColdMisses();

    void Print(std::ofstream& f, uint32_t sysid);

    // re-implemented by Exclusive/InclusiveCacheLevel
    virtual uint32_t Process(CacheStats* stats, uint32_t memid, uint64_t addr, 
      uint64_t loadstoreflag, bool* anyEvict, void* info);
    virtual uint32_t EvictProcess(CacheStats* stats, uint32_t memid, uint64_t 
      addr, uint64_t loadstoreflag, void* info);    

    virtual void EvictDirty(CacheStats* stats, CacheLevel** levels, uint32_t 
      memid, void* info); // void* info is needed since eventually 'Process' 
      // needs to be called! 
    virtual bool GetEvictStatus();

    std::vector<uint64_t>* passEvictAddresses() { return toEvictAddresses;}

protected:

    uint64_t GetStorage(uint64_t addr);
    uint64_t GetAddress(uint64_t store);
    uint32_t GetSet(uint64_t addr);
    uint32_t LineToReplace(uint32_t setid);
    bool MultipleLines(uint64_t addr, uint32_t width);

    void MarkUsed(uint32_t setid, uint32_t lineid,uint64_t loadstoreflag);

    // re-implemented by HighlyAssociativeCacheLevel
    virtual bool Search(uint64_t addr, uint32_t* set, uint32_t* lineInSet);
    virtual uint64_t Replace(uint64_t addr, uint32_t setid, uint32_t lineid,uint64_t loadstoreflag);

    virtual const char* TypeString() = 0;
    virtual void Init (CacheLevel_Init_Interface);
    
   // Both store and lineid is being sent since while calling these methods we do not make distinction as whether the object belongs to CacheLevel or HighlyAssociateCacheLevel
    virtual void SetDirty(uint32_t setid, uint32_t lineid,uint64_t store);
    virtual void ResetDirty(uint32_t setid, uint32_t lineid,uint64_t store);
    virtual bool GetDirtyStatus(uint32_t setid, uint32_t lineid,uint64_t store);
};

class InclusiveCacheLevel : public virtual CacheLevel {
public:
    InclusiveCacheLevel() {}
    ~InclusiveCacheLevel() {}

    virtual void Init (CacheLevel_Init_Interface){
        CacheLevel::Init(CacheLevel_Init_Arguments);
        type = CacheLevelType_InclusiveLowassoc;
    }
    virtual const char* TypeString() { return "inclusive"; }
};

class ExclusiveCacheLevel : public virtual CacheLevel {
public:
    uint32_t FirstExclusive;
    uint32_t LastExclusive;

    ExclusiveCacheLevel() {}
    uint32_t Process(CacheStats* stats, uint32_t memid, uint64_t addr,uint64_t loadstoreflag,bool* anyEvict,void* info);
    virtual void Init (CacheLevel_Init_Interface, uint32_t firstExcl, uint32_t lastExcl){
        CacheLevel::Init(CacheLevel_Init_Arguments);
        type = CacheLevelType_ExclusiveLowassoc;
        FirstExclusive = firstExcl;
        LastExclusive = lastExcl;
    }
    virtual const char* TypeString() { return "exclusive"; }
};

class NonInclusiveCacheLevel : public virtual CacheLevel {
public:
    uint32_t FirstExclusive;
    uint32_t LastExclusive;

    NonInclusiveCacheLevel() {}
    uint32_t Process(CacheStats* stats, uint32_t memid, uint64_t addr, uint64_t
      loadstoreflag,bool* anyEvict,void* info);
    virtual void Init(CacheLevel_Init_Interface){
        CacheLevel::Init(CacheLevel_Init_Arguments);
        type = CacheLevelType_NonInclusiveLowassoc;
    }
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
    uint64_t Replace(uint64_t addr, uint32_t setid, uint32_t lineid,uint64_t loadstoreflag);
    virtual void Init (CacheLevel_Init_Interface);

   // Both store and lineid is being sent since while calling these methods we do not make distinction as whether the object belongs to CacheLevel or HighlyAssociateCacheLevel
   void SetDirty(uint32_t setid, uint32_t lineid,uint64_t store);
   void ResetDirty(uint32_t setid, uint32_t lineid,uint64_t store);
   bool GetDirtyStatus(uint32_t setid, uint32_t lineid,uint64_t store);  
};

class HighlyAssociativeInclusiveCacheLevel : public InclusiveCacheLevel, public HighlyAssociativeCacheLevel {
public:
    HighlyAssociativeInclusiveCacheLevel() {}
    virtual void Init (CacheLevel_Init_Interface){
        InclusiveCacheLevel::Init(CacheLevel_Init_Arguments);
        HighlyAssociativeCacheLevel::Init(CacheLevel_Init_Arguments);
        type = CacheLevelType_InclusiveHighassoc;
    }
    const char* TypeString() { return "inclusive_H"; }
};

class HighlyAssociativeExclusiveCacheLevel : public ExclusiveCacheLevel, public HighlyAssociativeCacheLevel {
public:
    HighlyAssociativeExclusiveCacheLevel() {}
    virtual void Init (CacheLevel_Init_Interface, uint32_t firstExcl, uint32_t lastExcl){
        ExclusiveCacheLevel::Init(CacheLevel_Init_Arguments, firstExcl, lastExcl);
        HighlyAssociativeCacheLevel::Init(CacheLevel_Init_Arguments);
        type = CacheLevelType_ExclusiveHighassoc;
    }
    const char* TypeString() { return "exclusive_H"; }
};

class CacheStructureHandler : public MemoryStreamHandler {
public:
    uint32_t sysId;
    uint32_t levelCount;
    uint32_t hybridCache;

    uint64_t* RamAddressStart;
    uint64_t* RamAddressEnd;    

    CacheLevel** levels;
    std::string description;

protected: 
      uint32_t MinimumHighAssociativity = 256;
      uint32_t LoadStoreLogging = 0;
      uint32_t DirtyCacheHandling = 0;

      bool isInitialized = false;

      uint64_t hits;
      uint64_t misses;
      uint64_t AddressRangesCount;
      std::vector<uint64_t>* toEvictAddresses;
      uint32_t processAddress(void* stats, uint64_t address, uint64_t memseq, uint8_t loadstoreflag);

public:      
    // note that this doesn't contain any stats gathering code. that is done at the
    // thread level and is therefore done in ThreadData

    CacheStructureHandler();
    CacheStructureHandler(CacheStructureHandler& h);
    ~CacheStructureHandler();
    bool Init(std::string desc, uint32_t MinimumHighAssociativity, 
	  uint32_t LoadStoreLogging, uint32_t DirtyCacheHandling);

    void Print(std::ofstream& f);
    uint32_t Process(void* stats, BufferEntry* access);
    bool Verify();

    uint64_t GetHits(){return hits;}
    uint64_t GetMisses(){ return misses;} 

    bool CheckRange(CacheStats* stats,uint64_t addr,uint64_t loadstoreflag,uint32_t memid); //, uint32_t* set, uint32_t* lineInSet);    
    void ExtractAddresses();
};


#endif /* _CacheSimulation_hpp_ */
