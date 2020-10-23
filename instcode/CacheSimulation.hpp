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

#ifndef _Simulation_hpp_
#define _Simulation_hpp_

#include <string>
//#include <Metasim.hpp>
#include <AddressStreamStats.hpp>

using namespace std;

#define DEFAULT_CACHE_FILE "instcode/CacheDescriptions.txt"
#define DEFAULT_SAMPLE_ON  1000000
#define DEFAULT_SAMPLE_OFF 10000000
#define DEFAULT_SAMPLE_MAX 0

#define KILO (1024)
#define MEGA (KILO*KILO)
#define GIGA (MEGA*KILO)

#define INVALID_CACHE_LEVEL (0xffffffff)

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

static uint32_t RandomInt();
static uint32_t Low32(uint64_t f);
static uint32_t High32(uint64_t f);
static char ToLowerCase(char c);
static bool IsEmptyComment(string str);
static string GetCacheDescriptionFile();
static bool ParsePositiveInt32(string token, uint32_t* value);
static bool ParseInt32(string token, uint32_t* value, uint32_t min);
static bool ParsePositiveInt32Hex(string token, uint32_t* value);
static void ReadSettings();
static AddressStreamStats* GenerateStreamStats(AddressStreamStats* stats, 
  uint32_t typ, image_key_t iid, thread_key_t tid, image_key_t firstimage);
static uint64_t ReferenceStreamStats(AddressStreamStats* stats);
static void DeleteStreamStats(AddressStreamStats* stats);
static bool ReadEnvUint32(string name, uint32_t* var);
static void PrintAddressStreamStats(ofstream& f, AddressStreamStats* stats, 
  thread_key_t tid, bool perThread);
static void SimulationFileName(AddressStreamStats* stats, string& oFile);
static void RangeFileName(AddressStreamStats* stats, string& oFile);

extern "C" {
    void* tool_mpi_init();
    void* tool_thread_init(pthread_t tid);
    void* process_buffer(image_key_t* key);
    void* tool_image_fini(image_key_t* key);
};

class StreamStats {
public:
    virtual uint64_t GetAccessCount(uint32_t memid) = 0;
    virtual bool Verify() = 0;
};

class CacheStats : public StreamStats {
public:
    uint32_t LevelCount;
    uint32_t SysId;
    LevelStats** Stats; // indexed by [memid][level]
    LevelStats* HybridMemStats; // indexed by [memid]
    uint32_t Capacity;
    uint32_t hybridCache;
    CacheStats(uint32_t lvl, uint32_t sysid, uint32_t capacity, uint32_t 
      hybridCache);
    ~CacheStats();

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


#define INVALID_REUSE_DISTANCE (-1)

class SamplingMethod {
public:
    uint32_t AccessLimit;
    uint32_t SampleOn;
    uint32_t SampleOff;
    uint64_t AccessCount;

    SamplingMethod(uint32_t limit, uint32_t on, uint32_t off);
    ~SamplingMethod();

    void Print();

    void IncrementAccessCount(uint64_t count);

    bool SwitchesMode(uint64_t count);
    bool CurrentlySampling();
    bool CurrentlySampling(uint64_t count);
    bool ExceedsAccessLimit(uint64_t count);
};

#define USES_MARKERS(__pol) (__pol == ReplacementPolicy_nmru)
#define CacheLevel_Init_Interface uint32_t lvl, uint32_t sizeInBytes, uint32_t assoc, uint32_t lineSz, ReplacementPolicy pol
#define CacheLevel_Init_Arguments lvl, sizeInBytes, assoc, lineSz, pol

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

    uint64_t** contents;
    bool**  dirtystatus;
    uint32_t* recentlyUsed;
    history** historyUsed;
    bool toEvict;

public:
    vector<uint64_t>* toEvictAddresses;
    CacheLevel();
    ~CacheLevel();

    bool IsExclusive() { return (type == CacheLevelType_ExclusiveLowassoc || 
      type == CacheLevelType_ExclusiveHighassoc); }

    uint32_t GetLevelCount() { return levelCount;}
    uint32_t SetLevelCount(uint32_t inpLevelCount) { return levelCount = 
      inpLevelCount; }
    CacheLevelType GetType() { return type; }
    ReplacementPolicy GetReplacementPolicy() { return replpolicy; }
    uint32_t GetLevel() { return level; }
    uint32_t GetSizeInBytes() { return size; }
    uint32_t GetAssociativity() { return associativity; }
    uint32_t GetSetCount() { return countsets; }
    uint32_t GetLineSize() { return linesize; }
    uint64_t CountColdMisses();

    void Print(ofstream& f, uint32_t sysid);

    // re-implemented by Exclusive/InclusiveCacheLevel
    virtual uint32_t Process(CacheStats* stats, uint32_t memid, uint64_t addr, 
      uint64_t loadstoreflag, bool* anyEvict, void* info);
    virtual uint32_t EvictProcess(CacheStats* stats, uint32_t memid, uint64_t 
      addr, uint64_t loadstoreflag, void* info);    

    virtual void EvictDirty(CacheStats* stats, CacheLevel** levels, uint32_t 
      memid, void* info); // void* info is needed since eventually 'Process' 
      // needs to be called! 
    virtual bool GetEvictStatus();

    vector<uint64_t>* passEvictAddresses() { return toEvictAddresses;}

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

typedef enum {
    StreamHandlerType_undefined = 0,
    StreamHandlerType_CacheStructure,
    StreamHandlerType_AddressRange,
    StreamHandlerType_Total
} StreamHandlerTypes;

// DFP and other interesting memory things extend this class.
class MemoryStreamHandler {
protected:
    pthread_mutex_t mlock;
public:
    MemoryStreamHandler();
    ~MemoryStreamHandler();

    virtual void Print(ofstream& f) = 0;
    virtual uint32_t Process(void* stats, BufferEntry* access) = 0;
    virtual bool Verify() = 0;
    bool Lock();
    bool UnLock();
    bool TryLock();

    static StreamHandlerTypes FindType(string desc) { return StreamHandlerType_CacheStructure; }
};

class CacheStructureHandler : public MemoryStreamHandler {
public:
    uint32_t sysId;
    uint32_t levelCount;
    uint32_t hybridCache;

    uint64_t* RamAddressStart;
    uint64_t* RamAddressEnd;    

    CacheLevel** levels;
    string description;

protected: 
      uint64_t hits;
      uint64_t misses;
      uint64_t AddressRangesCount;
      vector<uint64_t>* toEvictAddresses;
      uint32_t processAddress(void* stats, uint64_t address, uint64_t memseq, uint8_t loadstoreflag);

public:      
    // note that this doesn't contain any stats gathering code. that is done at the
    // thread level and is therefore done in ThreadData

    CacheStructureHandler();
    CacheStructureHandler(CacheStructureHandler& h);
    ~CacheStructureHandler();
    bool Init(string desc);

    void Print(ofstream& f);
    uint32_t Process(void* stats, BufferEntry* access);
    bool Verify();

    uint64_t GetHits(){return hits;}
    uint64_t GetMisses(){ return misses;} 

    bool CheckRange(CacheStats* stats,uint64_t addr,uint64_t loadstoreflag,uint32_t memid); //, uint32_t* set, uint32_t* lineInSet);    
    void ExtractAddresses();
};


#endif /* _Simulation_hpp_ */