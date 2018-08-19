#ifndef _AddressStreamStats_hpp_
#define _AddressStreamStats_hpp_

//#define debug(...) __VA_ARGS__
#define debug(...)

enum EntryType: uint8_t {
  MEM_ENTRY = 0,
  PREFETCH_ENTRY,
  VECTOR_ENTRY
};

struct VectorAddress {
    uint32_t indexVector[16];
    uint64_t base;
    uint8_t  scale;
    uint64_t mask;
};

typedef struct {
    enum EntryType type;
    uint8_t        loadstoreflag;   // Dirty Caching
    uint64_t       imageid;         // Multi-image
    uint64_t       memseq;          // identifies memop in image
    union {
        uint64_t address;        // value simulated
        struct VectorAddress vectorAddress;
    };
//    uint64_t    threadid;        // Error-checking
//    uint64_t    programAddress;  // only used for adamant
} BufferEntry;
#define __buf_current  address
#define __buf_capacity memseq

class StreamStats;
class MemoryStreamHandler;
class ReuseDistance;

typedef struct{
    uint64_t GroupId; // for now, same as BB-ID/ Top-most loop of 
    uint32_t InnerLevelSize;
    uint64_t GroupCount;
    uint64_t* InnerLevelBasicBlocks; // Since there can be >1 
} NestedLoopStruct;

typedef struct {
    // memory buffer
    BufferEntry* Buffer;

    // metadata
    thread_key_t threadid;
    image_key_t imageid;
    bool Initialized;
    bool PerInstruction;
    bool LoopInclusion; // when terminating sampling for a block,
                        // do this for all blocks within the loop
                        // Note: includes all other blocks in the loop
    bool Master;
    uint32_t Phase;
    uint32_t AllocCount;
    uint32_t BlockCount;
    uint32_t GroupCount;
    uint32_t MemopCount;
    char* Application;
    char* Extension;

    // per-memop data
    uint64_t* BlockIds;   // Indices into per-block data, like counter
    uint64_t* MemopIds;   // Not entirely sure what this is used for

    // per-block data
    CounterTypes* Types; // ??
    uint64_t* Counters;
    uint32_t* MemopsPerBlock;
    char** Files;
    uint32_t* Lines;
    char** Functions;
    uint64_t* Hashes;
    uint64_t* Addresses;
    uint64_t* GroupIds;
    StreamStats** Stats; // indexed by handler
    MemoryStreamHandler** Handlers;
    ReuseDistance** RHandlers;

    // per-group data
//    uint32_t GroupSize;
    uint64_t* GroupCounters;

    //uint64_t NestedLoopCount;
    //NestedLoopStruct* NLStats;

} SimulationStats;

#define BUFFER_ENTRY(__stats, __n) (&(__stats->Buffer[__n+1]))
#define BUFFER_CAPACITY(__stats) (__stats->Buffer[0].__buf_capacity)
#define BUFFER_CURRENT(__stats) (__stats->Buffer[0].__buf_current)


#endif // _AddressStreamStats_hpp_
