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

#include <AddressStreamIntercept.h>

#include <BasicBlock.h>
#include <Function.h>
#include <Instrumentation.h>
#include <X86Instruction.h>
#include <X86InstructionFactory.h>
#include <LineInformation.h>
#include <Loop.h>
#include <TextSection.h>

#define ENTRY_FUNCTION "tool_image_init"
#define SIM_FUNCTION "process_buffer"
#define EXIT_FUNCTION "tool_image_fini"
#define INST_LIB_NAME "libaddrrange.so"

#define NOSTRING "__pebil_no_string__"
#define BUFFER_ENTRIES 0x10000

#define PREFETCH 2
#define LOAD 1
#define STORE 0

extern "C" {
    InstrumentationTool* AddressStreamInterceptMaker(ElfFile* elf){
        return new AddressStreamIntercept(elf);
    }
}

// TODO Move this to a place that makes more sense (a user API or even in Base)
// Function to sort Basic Blocks by hash value
int compareBBHash(const void* lhs, const void* rhs) {
    BasicBlock* leftBB = (BasicBlock*)lhs;
    BasicBlock* rightBB = (BasicBlock*)rhs;
    if(leftBB->getHashCode().getValue() < 
      rightBB->getHashCode().getValue()) {
        std::cout << "ACC: 0x" << std::hex << leftBB->getHashCode().getValue() 
          << " is LESS THAN 0x" << rightBB->getHashCode().getValue() 
          << std::endl;
        return 1;
    } else if (leftBB->getHashCode().getValue() == 
      rightBB->getHashCode().getValue()) {
        std::cout << "ACC: 0x" << std::hex << leftBB->getHashCode().getValue() 
          << " is EQUAL TO 0x" << rightBB->getHashCode().getValue() 
          << std::endl;
        return 0;
    } else {
        std::cout << "ACC: 0x" << std::hex << leftBB->getHashCode().getValue() 
          << " is MORE THAN 0x" << rightBB->getHashCode().getValue() 
          << std::endl;
        return -1;
    }
}

// Construct the Address Stream Interception Tool
AddressStreamIntercept::AddressStreamIntercept(ElfFile* elf)
    : InstrumentationTool(elf)
{
    memBufferFunc = NULL;
    exitFunc = NULL;
    entryFunc = NULL;

   // ASSERT(isPowerOfTwo(sizeof(BufferEntry)));
   // PRINT_WARN(20,"\n\t WARNING: sizeof(BufferEntry) is not checked for being power of two!!! ");
}

// Destruct an Address Stream Instrumentation Tool
AddressStreamIntercept::~AddressStreamIntercept(){
}

// Set up null line info value
void AddressStreamIntercept::allocateNullLineInfoValue() {
    // ACC -- > Assert not allocated
    nullLineInfoValue = reserveDataOffset(strlen(NOSTRING) + 1);
    initializeReservedData(getInstDataAddress() + nullLineInfoValue, 
      strlen(NOSTRING) + 1, NOSTRING);

}

// Allocate space for Simulation Stats Structure
void AddressStreamIntercept::allocateSimulationStats(uint64_t extra) {
    // ACC -- > Assert not allocated
    simulationStatsOffset = reserveDataOffset(sizeof(SimulationStats) + extra);
//                         (sizeof(uint64_t) * stats.BlockCount));

}

// Declare libraries and runtime functions
void AddressStreamIntercept::declare(){
    InstrumentationTool::declare();
    
    // declare any shared library that will contain instrumentation functions
    declareLibrary(INST_LIB_NAME);

    // declare any instrumentation functions that will be used
    memBufferFunc = declareFunction(SIM_FUNCTION);
    ASSERT(memBufferFunc && "Cannot find memory print function, are you sure it was declared?");
    exitFunc = declareFunction(EXIT_FUNCTION);
    ASSERT(exitFunc && "Cannot find exit function, are you sure it was declared?");
    entryFunc = declareFunction(ENTRY_FUNCTION);
    ASSERT(entryFunc && "Cannot find entry function, are you sure it was declared?");
}

uint64_t AddressStreamIntercept::getNullLineInfoValue() {
  
    if(nullLineInfoValue == 0) { 
        PRINT_ERROR("Never allocated space for a null line info value. Do "
          "this with allocateNullLineInfoValue()");
    }
    return nullLineInfoValue;
}

// Get the number of blocks to instrument
uint32_t AddressStreamIntercept::getNumberOfBlocksToInstrument() {
    // This used to go through blocks in binary and see if the block
    // was in blocksToInstHash. This made sure that instrumented blocks
    // existed in binary and there were no duplicates.

    // However, the SimpleHash data structure handles duplicates
    // and the initialization SHOULD handle if the block exists
    // in the binary. So, for now, just use size
    return blocksToInst.size();
}

// Get number of groups created
uint64_t AddressStreamIntercept::getNumberOfGroups() {
    // Go through mapBBToGrouId and find maximum group id
    // Group IDs start at 0, so add one to final number
    uint64_t maxId = 0;
    ASSERT(mapBBToGroupId.size() > 0);
    uint64_t* allIds = mapBBToGroupId.values();

    for (uint32_t i = 0; i < mapBBToGroupId.size(); i++) {
        if (allIds[i] > maxId) {
            maxId = allIds[i];
        }
    } // For each BB's group id

    return (maxId + 1);
}

// Get the number of memops to instrument
// Note: Some insns can contain multiple memops!
uint32_t AddressStreamIntercept::getNumberOfMemopsToInstrument(){

    uint32_t numMemops = 0;
    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        ASSERT(blocksToInstHash.get(bb->getHashCode().getValue()));

            for (uint32_t j = 0; j < bb->getNumberOfInstructions(); j++){
                X86Instruction* memop = bb->getInstruction(j);
                numMemops += getNumberOfMemopsToInstrument(memop);
            }
    }

    return numMemops;
}

// Returns number of memops in insn that we are instrumenting
uint64_t AddressStreamIntercept::getNumberOfMemopsToInstrument(X86Instruction* 
  insn) {
    uint64_t numMemops = 0;
    // TODO: assert that the insn exists
    if (insn->isLoad() && ifInstrumentingLoads()){
        numMemops++;
    }
    if (insn->isStore() && ifInstrumentingStores()){
        numMemops++;
    }
    if (insn->isSoftwarePrefetch() && ifInstrumentingSWPrefetches()){
        numMemops++;
    }

    return numMemops;
}

uint64_t AddressStreamIntercept::getSimulationStatsOffset() {
  
    if(simulationStatsOffset == 0) { 
        PRINT_ERROR("Never allocated space for the Simulation Stats structure. "
          "Do this with allocateSimulationStats()");
    }
    return simulationStatsOffset;
}

// Returns true if instruction has memops that we are instrumenting
bool AddressStreamIntercept::ifInstrumentingInstruction(X86Instruction* 
  insn) {
    // TODO: assert that the insn exists
    if (getNumberOfMemopsToInstrument(insn) > 0){
        return true;
    }
    return false;
}


// Read input file and create a list of blocks to instrument
// initializes blocksToInstHash
void AddressStreamIntercept::initializeBlocksToInst(){

    // Initialize BlocksToInstHash
    if (!strcmp("+", inputFile)){
        for (uint32_t i = 0; i < getNumberOfExposedBasicBlocks(); i++){
            BasicBlock* bb = getExposedBasicBlock(i);
            blocksToInstHash.insert(bb->getHashCode().getValue(), bb);
        }
    } else {
        Vector<char*> fileLines;
        initializeFileList(inputFile, &fileLines);

        for (uint32_t i = 0; i < fileLines.size(); i++){
            char* ptr = strchr(fileLines[i],'#');
            if(ptr) *ptr = '\0';

            if(!strlen(fileLines[i]) || allSpace(fileLines[i]))
                continue;

            int32_t err;
            uint64_t inputHash = 0;
            uint64_t imgHash = 0;

            err = sscanf(fileLines[i], "%llx %llx", &inputHash, &imgHash);
            if(err <= 0){
                PRINT_ERROR("Line %d of %s has a wrong format", i+1, inputFile);
            }

            // First number is a blockhash
            HashCode* hashCode = new HashCode(inputHash);

            // Second number, if present, is image id
            if(err == 2 && getElfFile()->getUniqueId() != imgHash)
                continue;
            
            BasicBlock* bb = findExposedBasicBlock(*hashCode);
            delete hashCode;

            if (!bb){
                PRINT_WARN(10, "cannot find basic block for hash code %#llx "
                  "found in input file", inputHash);
                continue;
            }
            blocksToInstHash.insert(bb->getHashCode().getValue(), bb);

            //TODO Refactor group stuff
            includeLoopBlocks(bb);

            // By default, also insert blocks in the same loop
            // TODO: Shut this off with a flag
            if (bb->isInLoop()){
                FlowGraph* fg = bb->getFlowGraph();
                Loop* lp = fg->getInnermostLoopForBlock(bb->getIndex());
                BasicBlock** allBlocks = new BasicBlock*[
                  lp->getNumberOfBlocks()];
                lp->getAllBlocks(allBlocks);
                
                BasicBlock* headBB = lp->getHead(); 
                uint64_t topLoopID = headBB->getHashCode().getValue();

                for (uint32_t k = 0; k < lp->getNumberOfBlocks(); k++){
                    uint64_t code = allBlocks[k]->getHashCode().getValue();
                    blocksToInstHash.insert(code, allBlocks[k]);
                }                      
            }

        }

        for (uint32_t i = 0; i < fileLines.size(); i++){
            delete[] fileLines[i];
        }
    }

    // Initialize BlocksToInst
    BasicBlock** blocksInHash = blocksToInstHash.values();
    ASSERT((blocksInHash != NULL) && "Could not find blocks to instrument.");
    std::cout << "ACC: Creating BlocksToInst" << std::endl;
    for (uint32_t i = 0; i < blocksToInstHash.size(); i++){
        BasicBlock* bb = blocksInHash[i];
        //blocksToInst.push_back(bb);
        //blocksToInst.insertSorted(bb, compareBBHash);
        blocksToInst.insertSorted(bb, compareBaseAddress);
    }
    
    std::cout << "ACC: Printing BlocksToInst" << std::endl;
    for (uint32_t i = 0; i < blocksToInst.size(); i++){
        BasicBlock* bb = blocksToInst[i];
        std::cout << "ACC: Block " << i << " is block 0x" << std::hex <<
          bb->getHashCode().getValue() << std::endl;
    }

/*** ACC --> Remove this code? ***/
//    // Default Behavior
//    ASSERT(blocksToInstHash.size() && "Cache Simulation did not find any blocks to instrument.");
//    if (!blocksToInstHash.size()){
//        // for executables, instrument everything
//        if (getElfFile()->isExecutable()){
//            for (uint32_t i = 0; i < getNumberOfExposedBasicBlocks(); i++){
//                BasicBlock* bb = getExposedBasicBlock(i);
//                blocksToInstHash.insert(bb->getHashCode().getValue(), bb);
//            }
//        }
//        // for shared libraries, just instrument the entry block
//        else {
//            BasicBlock* bb = getProgramEntryBlock();
//            blocksToInstHash.insert(bb->getHashCode().getValue(), bb);
//        }
//    }
}

// Initialize special buffer entry
void AddressStreamIntercept::initializeFirstBufferEntry(BufferEntry& intro){
    intro.__buf_current = 0;
    intro.__buf_capacity = BUFFER_ENTRIES;
}

// Initialize groups for sampling (blocks that are turned on and off together)
// In this function, we assume that all blocks in the same loop are in the 
// same group
void AddressStreamIntercept::initializeGroups() {
    // Start group ids at 0
    uint64_t nextGroupId = 0;   // Increases when a new groupd is created
    uint64_t currGroupId = 0;   // current group ID
    // This is a temporary structure to help create mapBBToGroupId
    // (Theoretically, blocks that aren't going to be instrumented could go in
    // mapBBToGroupId, but for now we will limit that structure to only blocks
    // that will be instrumented)
    SimpleHash<uint64_t> mapBBHeadsToGroupId;

    std::cout << "ACC: Initialize groups" << std::endl;
    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        ASSERT((blocksToInstHash.get(bb->getHashCode().getValue())))
        std::cout << "ACC: Adding block 0x" << std::hex << 
            bb->getHashCode().getValue() << "to groups" << std::endl;
        // If the BB has already been added to map, then done!
        // If not, then figure out which group it should be in
        if (!mapBBToGroupId.get(bb->getHashCode().getValue())) {
            // If the BB is in a loop, see if that loop head has a group
            if (bb->isInLoop()){
                FlowGraph* fg = bb->getFlowGraph();
                Loop* lp = fg->getInnermostLoopForBlock(bb->getIndex());
        
                BasicBlock* headBB = lp->getHead(); 
                uint64_t topLoopId = headBB->getHashCode().getValue();
                // If this group has an ID, get the group ID
                if (mapBBHeadsToGroupId.get(topLoopId)) {
                    currGroupId = mapBBHeadsToGroupId.getVal(topLoopId);
                } else {
                    // Else, create a new group
                    currGroupId = nextGroupId;
                    nextGroupId++;
                    mapBBHeadsToGroupId.insert(topLoopId, currGroupId);
                }

            } else { 
                // Else, bb is not in a loop and create a new group
                currGroupId = nextGroupId;
                nextGroupId++;
            } // bb is in loop

            // Add this BB to map
            mapBBToGroupId.insert(bb->getHashCode().getValue(), currGroupId);
        } // BB has group Id
    } // for each block
} 

// Allocate and initialize pointers for the runtime Simulation Stats structure
void AddressStreamIntercept::initializeSimulationStats(SimulationStats& stats) {

    // Allocate Memory Buffer
    // first entry in buffer is treated specially
    BufferEntry intro;
    initializeFirstBufferEntry(intro);
    stats.Buffer = (BufferEntry*)reserveDataOffset((sizeof(BufferEntry) * 
      (BUFFER_ENTRIES + 1)));
    initializeReservedData(getInstDataAddress() + (uint64_t)stats.Buffer,
                           sizeof(BufferEntry),
                           &intro);

    // Next, set metadata
    // ACC --> Should we initialize threadid and imageid?
    stats.Initialized = true;
    if (isPerInstruction()){
        stats.PerInstruction = true;
        stats.BlockCount = getNumberOfMemopsToInstrument();
    } else {
        stats.PerInstruction = false;
        stats.BlockCount = getNumberOfBlocksToInstrument();
    }
    stats.LoopInclusion = loopIncl;
    stats.Master = isMasterImage();
    stats.Phase = phaseNo;
    stats.MemopCount = getNumberOfMemopsToInstrument();
    std::cout << "ACC: Setting MemopCount to " << std::dec << stats.MemopCount
      << std::endl;
    stats.GroupCount = getNumberOfGroups();
    std::cout << "ACC: Setting GroupCount to " << std::dec << stats.GroupCount
      << std::endl;

    // Allocate Counters and SimulationStats contiguously to
    // avoid an extra memory ref in counter updates
    // Pass Counters as extra space to be allocated
    allocateSimulationStats((sizeof(uint64_t) * stats.BlockCount));
    uint64_t statsOffset = getSimulationStatsOffset();

    // Set Counters to point to extra space
    stats.Counters = (uint64_t*)(statsOffset + sizeof(SimulationStats));
    initializeReservedPointer((uint64_t)stats.Counters, statsOffset +
        offsetof(SimulationStats, Counters));

    // Set Buffer pointer
    initializeReservedPointer((uint64_t)stats.Buffer,
        statsOffset + offsetof(SimulationStats, Buffer));


    // Set string metadata
    char* appName = getElfFile()->getAppName();
    uint64_t app = reserveDataOffset(strlen(appName) + 1);
    initializeReservedPointer(app, statsOffset + 
      offsetof(SimulationStats, Application));
    initializeReservedData(getInstDataAddress() + app, strlen(appName) + 1, 
      (void*)appName);

    char extName[__MAX_STRING_SIZE];
    sprintf(extName, "%s\0", getExtension());
    uint64_t ext = reserveDataOffset(strlen(extName) + 1);
    initializeReservedPointer(ext, statsOffset + 
      offsetof(SimulationStats, Extension));
    initializeReservedData(getInstDataAddress() + ext, strlen(extName) + 1, 
      (void*)extName);

    // Per-Memop Data
    // Initialize just pointer for now
    // Data initializing will happen later 
#define INIT_INSN_ELEMENT(__typ, __nam)\
    stats.__nam = (__typ*)reserveDataOffset(stats.MemopCount * sizeof(__typ));  \
    initializeReservedPointer((uint64_t)stats.__nam, statsOffset + offsetof(SimulationStats, __nam))

    INIT_INSN_ELEMENT(uint64_t, BlockIds);
    INIT_INSN_ELEMENT(uint64_t, MemopIds);

    // Initialize BlockIds
    // If perinsn, give each memop a unique ID
    uint64_t blockSeq = 0;
    uint64_t memopSeq = 0;
    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        Function* func = (Function*)bb->getLeader()->getContainer();

        // Check if we should skip this block
        if (!blocksToInstHash.get(bb->getHashCode().getValue()))
            continue;

        // Go through each memop
        // NOTE: Some insns have multiple memops!
        for (uint32_t j = 0; j < bb->getNumberOfInstructions(); j++){
            X86Instruction* memop = bb->getInstruction(j);
            for (uint64_t m = 0; m < getNumberOfMemopsToInstrument(memop); m++)
            {
                if (isPerInstruction()) {
                    initializeReservedData(getInstDataAddress() + 
                      (uint64_t)stats.BlockIds + memopSeq*sizeof(uint64_t), 
                      sizeof(uint64_t), &memopSeq);
                } else {
                    initializeReservedData(getInstDataAddress() + 
                      (uint64_t)stats.BlockIds + memopSeq*sizeof(uint64_t), 
                      sizeof(uint64_t), &blockSeq);
                }

                // Also initialize memop ids. These are currnetly only
                // used in perinsn code and should probably be refactored
                // TODO Refactor this
                //initializeReservedData(getInstDataAddress() + 
                //  (uint64_t)stats.MemopIds + memopSeq*sizeof(uint64_t), 
                //  sizeof(uint64_t), &blockSeq);

                memopSeq++;
            }
        }
        blockSeq++;
    }


    // Per-Block Data
    // Again, just initialize the point
    // Data to be initialized later
#define INIT_BLOCK_ELEMENT(__typ, __nam)\
    stats.__nam = (__typ*)reserveDataOffset(stats.BlockCount * sizeof(__typ));  \
    initializeReservedPointer((uint64_t)stats.__nam, statsOffset + offsetof(SimulationStats, __nam))

    INIT_BLOCK_ELEMENT(CounterTypes, Types);
    // Counters alread initialized
    INIT_BLOCK_ELEMENT(uint32_t, MemopsPerBlock);
    INIT_BLOCK_ELEMENT(char*, Files);
    INIT_BLOCK_ELEMENT(uint32_t, Lines);
    INIT_BLOCK_ELEMENT(char*, Functions);
    INIT_BLOCK_ELEMENT(uint64_t, Hashes);
    //ACC UNUSED
    INIT_BLOCK_ELEMENT(uint64_t, Addresses);
    INIT_BLOCK_ELEMENT(uint64_t, GroupIds);

    // Initialize the Types and Counters
    // Counters set up like BasicBlockCounter Counters
    // The first instruction (memop) in the block keeps the count
    // The other instructions (memops) hold the index to of the first insn
    // The first memop is CounterTypes_basicBlock
    // Other memops in the block are type CounterTypes_instruction
    // Also collect number of memops per block
    CounterTypes counterType = CounterType_basicblock;
    uint64_t firstMemopId = 0;
    bool isFirstMemopInBlock = false;
    blockSeq = 0;
    memopSeq = 0;
    uint64_t initCounterValue = 0;
    uint64_t counterIndex = 0;
    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        Function* func = (Function*)bb->getLeader()->getContainer();

        // Check if we should skip this block
        if (!blocksToInstHash.get(bb->getHashCode().getValue()))
            continue;

        // Go through each memop
        isFirstMemopInBlock = true;
        for (uint32_t j = 0; j < bb->getNumberOfInstructions(); j++){
            X86Instruction* memop = bb->getInstruction(j);
            for (uint64_t m = 0; m < getNumberOfMemopsToInstrument(memop); m++)
            { 
                if (isFirstMemopInBlock || !(isPerInstruction())) {
                    firstMemopId = memopSeq;
                    counterType = CounterType_basicblock;
                    initCounterValue = 0;
                } else {
                    counterType = CounterType_instruction;
                    initCounterValue = firstMemopId;
                }
                if (isPerInstruction()) {
                    counterIndex = memopSeq;
                } else {
                    counterIndex = blockSeq;
                }
                initializeReservedData(getInstDataAddress() + 
                  (uint64_t)stats.Types + (counterIndex * sizeof(CounterTypes)),
                  sizeof(CounterTypes), &counterType);
                initializeReservedData(getInstDataAddress() + 
                  (uint64_t)stats.Counters + (counterIndex * sizeof(uint64_t)),
                  sizeof(uint64_t), &initCounterValue);
                memopSeq++;
                isFirstMemopInBlock = false;
            }
        }
        blockSeq++;
    }

    // Collect number of memops per block (with perinsn, we separate out each
    // memop from the insn, so set numMemops to 1)
    blockSeq = 0;
    memopSeq = 0;
    uint32_t numMemopsInBlock = 0;
    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        Function* func = (Function*)bb->getLeader()->getContainer();

        // Check if we should skip this block
        if (!blocksToInstHash.get(bb->getHashCode().getValue()))
            continue;

        numMemopsInBlock = 0;
        for (uint32_t j = 0; j < bb->getNumberOfInstructions(); j++){
            X86Instruction* memop = bb->getInstruction(j);
            for (uint64_t m = 0; m < getNumberOfMemopsToInstrument(memop); m++)
            { 
                // If perinsn, then set each to 1. Must go through with
                // sequence number
                if (isPerInstruction()) {
                    numMemopsInBlock = 1;
                    initializeReservedData(getInstDataAddress() + 
                      (uint64_t)stats.MemopsPerBlock + 
                      memopSeq*sizeof(uint32_t), sizeof(uint32_t), 
                      &numMemopsInBlock);
              } 
              numMemopsInBlock++;
              memopSeq++;
           }
        }
        // In not perinsn, then we set it to the number of memop
        if(!isPerInstruction()) {
            initializeReservedData(getInstDataAddress() + 
              (uint64_t)stats.MemopsPerBlock + blockSeq*sizeof(uint32_t),
              sizeof(uint32_t), &numMemopsInBlock);
        }
        blockSeq++;
    }

    // Initialize Files, Lines, and Functions
    blockSeq = 0;
    memopSeq = 0;
    uint64_t noData = getNullLineInfoValue();
    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        Function* func = (Function*)bb->getLeader()->getContainer();

        // Check if we should skip this block
        if (!blocksToInstHash.get(bb->getHashCode().getValue()))
            continue;

        for (uint32_t j = 0; j < bb->getNumberOfInstructions(); j++){
            X86Instruction* memop = bb->getInstruction(j);
            for (uint64_t m = 0; m < getNumberOfMemopsToInstrument(memop); m++)
            { 
                // If perinsn, then set Line Info by memopSeq
                if (isPerInstruction()) {
                    initializeLineInfo(stats, func, bb, memopSeq, noData);
                }
                memopSeq++;
           }
        }
        // In not perinsn, then we set it by blockSeq
        if(!isPerInstruction()) {
            initializeLineInfo(stats, func, bb, blockSeq, noData);
        }
        blockSeq++;
    }

    // Initialize Hashes and Groups
    blockSeq = 0;
    memopSeq = 0;
    uint64_t hashValue = 0;
    uint64_t bbHashValue = 0;
    uint64_t groupId = 0;

    initializeReservedData(
      getInstDataAddress() + (uint64_t)stats.GroupIds + (memopSeq * sizeof(uint64_t)),
      sizeof(uint64_t),
      &groupId);

    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        Function* func = (Function*)bb->getLeader()->getContainer();

        // Check if we should skip this block
        if (!blocksToInstHash.get(bb->getHashCode().getValue()))
            continue;

        bbHashValue = bb->getHashCode().getValue();
        // If perInsn, then need to give the memops hash value
        if (isPerInstruction()) {
            for (uint32_t j = 0; j < bb->getNumberOfInstructions(); j++){
                X86Instruction* memop = bb->getInstruction(j);
                for (uint64_t m = 0; m < getNumberOfMemopsToInstrument(memop); 
                  m++) { 
                    HashCode* memopHashCode = memop->generateHashCode(bb);
                    hashValue = memopHashCode->getValue();
                    initializeReservedData(getInstDataAddress() + 
                      (uint64_t)stats.Hashes + memopSeq*sizeof(uint64_t),
                      sizeof(uint64_t), &hashValue);

                    if(mapBBToGroupId.get(bbHashValue)) {
                        groupId = mapBBToGroupId.getVal(bbHashValue);
                    } else {
                        groupId = 0;
                    }

                    std::cout << "ACC: Setting Block ( 0x" << std::hex << 
                      hashValue << " ) to group " << std::dec << groupId 
                      << std::endl;

                    initializeReservedData(getInstDataAddress() + 
                      (uint64_t)stats.GroupIds + (memopSeq * sizeof(uint64_t)),
                      sizeof(uint64_t),&groupId);
                    memopSeq++;
                    delete memopHashCode;
                }
            }
        } else {
            // In not perinsn, then just set it to the block hash
            hashValue = bbHashValue;
            initializeReservedData(getInstDataAddress() + 
              (uint64_t)stats.Hashes + blockSeq*sizeof(uint64_t), 
              sizeof(uint64_t), &hashValue);


            if(mapBBToGroupId.get(hashValue)) {
                groupId = mapBBToGroupId.getVal(hashValue);
            } else {
                groupId = 0;
            }

            std::cout << "ACC: Setting Block ( 0x" << std::hex << hashValue << 
              " ) to group " << std::dec << groupId << std::endl;

            initializeReservedData(getInstDataAddress() + 
              (uint64_t)stats.GroupIds + (blockSeq * sizeof(uint64_t)),
              sizeof(uint64_t),&groupId);
        }
        blockSeq++;
    }

    // Per-Group Data
    // Initialize just pointer for now
    // Data initializing will happen later 
#define INIT_INSN_ELEMENT(__typ, __nam)\
    stats.__nam = (__typ*)reserveDataOffset(stats.GroupCount * sizeof(__typ));  \
    initializeReservedPointer((uint64_t)stats.__nam, statsOffset + offsetof(SimulationStats, __nam))

    INIT_INSN_ELEMENT(uint64_t, GroupCounters);

    // Initialize GroupCounts
    uint64_t initGroupCount = 0;
    for (uint64_t groupSeq = 0; groupSeq < stats.GroupCount; groupSeq++){
        initializeReservedData(getInstDataAddress() + 
          (uint64_t)stats.GroupCounters + groupSeq*sizeof(uint64_t), 
          sizeof(uint64_t), &initGroupCount);
    }



    stats.Stats = NULL;

    // Finally initialize SimulationStats
    initializeReservedData(
        getInstDataAddress() + statsOffset,
        sizeof(SimulationStats),
        (void*)(&stats));

}

// Instrument the program entry with a function to initialize the Address 
// stream tool
void AddressStreamIntercept::instrumentEntryPoint() {
     if (isMultiImage()){
        for (uint32_t i = 0; i < getNumberOfExposedFunctions(); i++){
            Function* f = getExposedFunction(i);

            InstrumentationPoint* point = addInstrumentationPoint(
                f, entryFunc, InstrumentationMode_tramp, InstLocation_prior);

            ASSERT(point);
            point->setPriority(InstPriority_sysinit);
            if (!point->getInstBaseAddress()){
                PRINT_ERROR("Cannot find an instrumentation point at the entry "
                  "function");
            }            

            dynamicPoint(point, getElfFile()->getUniqueId(), true);
        }
    } else {
        InstrumentationPoint* point = addInstrumentationPoint(
            getProgramEntryBlock(), entryFunc, InstrumentationMode_tramp);
        ASSERT(point);
        point->setPriority(InstPriority_sysinit);
        if (!point->getInstBaseAddress()){
            PRINT_ERROR("Cannot find an instrumentation point at the entry "
              "function");
        }
    }
}

// Instrument the program exit with a function to finalize the address stream 
// tool
void AddressStreamIntercept::instrumentExitPoint() {
    InstrumentationPoint* point = addInstrumentationPoint(
        getProgramExitBlock(), exitFunc, InstrumentationMode_tramp);
    ASSERT(point);
    point->setPriority(InstPriority_sysinit);
    if (!point->getInstBaseAddress()){
        PRINT_ERROR("Cannot find an instrumentation point at the exit function");
    }
}


// Also include any block that is in this loop (including child loops)
void AddressStreamIntercept::includeLoopBlocks(BasicBlock* bb) {
    if (bb->isInLoop()){
        SimpleHash<Loop*> loopsToCheck;
        Vector<Loop*> loopsVec;

        FlowGraph* fg = bb->getFlowGraph();
        Loop* lp = fg->getInnermostLoopForBlock(bb->getIndex());
        BasicBlock** allBlocks = new BasicBlock*[lp->getNumberOfBlocks()];
        lp->getAllBlocks(allBlocks);
        
        BasicBlock* HeadBB=lp->getHead(); 
        uint64_t topLoopID=HeadBB->getHashCode().getValue();

        for (uint32_t k = 0; k < lp->getNumberOfBlocks(); k++){
            uint64_t code = allBlocks[k]->getHashCode().getValue();
        //    blocksToInstHash.insert(code, allBlocks[k]);
        }                      
        // TODO: Should I delete the hashes/vectors used for book keeping of figuring out loop structure ?
        delete[] allBlocks;
    }/* else {
        if( !(mapBBToGroupId.get(bb->getHashCode().getValue())) ) {
            mapBBToGroupId.insert(bb->getHashCode().getValue(),bb->getHashCode().getValue()); 
        } // not in mapBBToGroupId
    } */// not in loop

}

void AddressStreamIntercept::initializeLineInfo(
        SimulationStats& stats,
        Function* func,
        BasicBlock* bb,
        uint32_t blockSeq,
        uint64_t noData) {

    LineInfo* li = NULL;
    LineInfoFinder* lineInfoFinder = NULL;

    if (hasLineInformation()){
        lineInfoFinder = getLineInfoFinder();
    }

    if (lineInfoFinder){
        li = lineInfoFinder->lookupLineInfo(bb);
    }
    //allBlockLineInfos.append(li);

    if (li){
        uint32_t line = li->GET(lr_line);
        initializeReservedData(
            getInstDataAddress() + (uint64_t)stats.Lines + sizeof(uint32_t)*blockSeq,
            sizeof(uint32_t),
            &line);

        uint64_t filename = reserveDataOffset(strlen(li->getFileName()) + 1);
        initializeReservedPointer(
            filename,
            (uint64_t)stats.Files + blockSeq*sizeof(char*));
        initializeReservedData(
            getInstDataAddress() + filename,
            strlen(li->getFileName()) + 1,
            (void*)li->getFileName());
    } else {
        uint32_t temp32 = 0;
        initializeReservedData(
            getInstDataAddress() + (uint64_t)stats.Lines + sizeof(uint32_t)*blockSeq,
            sizeof(uint32_t),
            &temp32);
        initializeReservedPointer(
            noData,
            (uint64_t)stats.Files + blockSeq*sizeof(char*));
    }
    uint64_t funcname = reserveDataOffset(strlen(func->getName()) + 1);
    initializeReservedPointer(funcname,
        (uint64_t)stats.Functions + blockSeq*sizeof(char*));
    initializeReservedData(
        getInstDataAddress() + funcname,
        strlen(func->getName()) + 1,
        (void*)func->getName());
}

// checks if buffer is full and conditionally clears it
void AddressStreamIntercept::insertBufferClear(
        uint32_t numMemops,
        X86Instruction* inst,
        InstLocations loc,
        uint64_t blockSeq,
        uint32_t threadReg,
        SimulationStats& stats)
{


    // grab 2 scratch registers
    uint32_t sr1 = X86_REG_INVALID, sr2 = X86_REG_INVALID;
    BitSet<uint32_t>* inv = new BitSet<uint32_t>(X86_ALU_REGS);
    inv->insert(X86_REG_AX);
    inv->insert(X86_REG_SP);
    inv->insert(X86_REG_BP);
    if (inv_reg) {
        inv->insert(get_reg());
    }

    if (threadReg != X86_REG_INVALID){
        inv->insert(threadReg);
        sr1 = threadReg;
    }
    for (uint32_t k = X86_64BIT_GPRS; k < X86_ALU_REGS; k++){
        inv->insert(k);
    }
    BitSet<uint32_t>* dead = inst->getDeadRegIn(inv, 2);
    ASSERT(dead->size() >= 2);
    for (uint32_t k = 0; k < X86_64BIT_GPRS; k++){
        if (dead->contains(k)){
            if (sr1 == X86_REG_INVALID){
                sr1 = k;
            } else if (sr2 == X86_REG_INVALID){
                sr2 = k;
                break;
            }
        }
    }
    ASSERT(sr1 != X86_REG_INVALID && sr2 != X86_REG_INVALID);
    delete inv;
    delete dead;

    // Create Instrumentation Point
    InstrumentationPoint* pt = addInstrumentationPoint(inst, memBufferFunc, InstrumentationMode_tramp, loc);
    pt->setPriority(InstPriority_userinit);
    dynamicPoint(pt, GENERATE_KEY(blockSeq, PointType_buffercheck), true);
    Vector<X86Instruction*>* bufferDumpInstructions = new Vector<X86Instruction*>();

    // if thread data addr is not in sr1 already, load it
    if (threadReg == X86_REG_INVALID && usePIC()){
        Vector<X86Instruction*>* tdata = storeThreadData(sr2, sr1);
        for (uint32_t k = 0; k < tdata->size(); k++){
            bufferDumpInstructions->append((*tdata)[k]);
        }
        delete tdata;
    }

    // put current buffer into sr2
    if (usePIC()){
        // sr2 =((SimulationStats)sr1)->Buffer
        bufferDumpInstructions->append(X86InstructionFactory64::emitMoveRegaddrImmToReg(sr1, offsetof(SimulationStats, Buffer), sr2));
    } else {
        // sr2 = stats.Buffer
        bufferDumpInstructions->append(X86InstructionFactory64::emitMoveImmToReg(getInstDataAddress() + (uint64_t)stats.Buffer, sr2));
    }
    // sr2 = ((BufferEntry)sr2)->__buf_current
    bufferDumpInstructions->append(X86InstructionFactory64::emitMoveRegaddrImmToReg(sr2, offsetof(BufferEntry, __buf_current), sr2));                            

    // compare current buffer+blockMemops to buffer max
    bufferDumpInstructions->append(X86InstructionFactory64::emitCompareImmReg(BUFFER_ENTRIES - numMemops, sr2));

    // jump to non-buffer-jump code
    bufferDumpInstructions->append(X86InstructionFactory::emitBranchJL(Size__64_bit_inst_function_call_support));

    ASSERT(bufferDumpInstructions);
    while (bufferDumpInstructions->size()){
        pt->addPrecursorInstruction(bufferDumpInstructions->remove(0));
    }
    delete bufferDumpInstructions;

    // Increment current buffer size
    // if we include the buffer increment as part of the buffer check, it increments
    // the buffer pointer even when we try to disable this point during buffer clearing
    InstrumentationSnippet* snip = addInstrumentationSnippet();
    pt = addInstrumentationPoint(inst, snip, InstrumentationMode_inline, loc);
    pt->setPriority(InstPriority_regular);
    dynamicPoint(pt, GENERATE_KEY(blockSeq, PointType_bufferinc), true);

    // sr1 = stats
    if (threadReg == X86_REG_INVALID && usePIC()){
        Vector<X86Instruction*>* tdata = storeThreadData(sr2, sr1);
        for (uint32_t k = 0; k < tdata->size(); k++){
            snip->addSnippetInstruction((*tdata)[k]);
        }
        delete tdata;
    }

    if (usePIC()){
        // sr2 = ((SimulationStats*)sr1)->Buffer
        snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegaddrImmToReg(
            sr1,
            offsetof(SimulationStats, Buffer),
            sr2));
        // ((BufferEntry*)sr2)->__buf_current++
        snip->addSnippetInstruction(X86InstructionFactory64::emitAddImmToRegaddrImm(
            numMemops,
            sr2,
            offsetof(BufferEntry, __buf_current)));
    } else {
        // stats.Buffer[0].__buf_current++
        uint64_t currentOffset = (uint64_t)stats.Buffer + offsetof(BufferEntry, __buf_current);
        snip->addSnippetInstruction(X86InstructionFactory64::emitAddImmToMem(
            numMemops,
            getInstDataAddress() + currentOffset));
    }
}

void AddressStreamIntercept::writeBufferBase(
        InstrumentationSnippet* snip,
        uint32_t sr2,
        uint32_t sr3,
        enum EntryType type,
        uint8_t loadstoreflag,
        uint32_t memseq) {

    // set entry type
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToReg(type, sr3));
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(sr3, sr2, offsetof(BufferEntry, type), true));
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToRegaddrImm(
        type,
        sizeof(type),
        sr2,
        offsetof(BufferEntry, type)));

    // set Load-store flag
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToReg(loadstoreflag, sr3));
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(sr3, sr2, offsetof(BufferEntry, loadstoreflag), true));
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToRegaddrImm(
        loadstoreflag,
        sizeof(loadstoreflag),
        sr2,
        offsetof(BufferEntry, loadstoreflag)));

    // set imageid
    uint64_t imageHash = getElfFile()->getUniqueId();
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImm64ToReg(imageHash, sr3));
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(sr3, sr2, offsetof(BufferEntry, imageid), true));

    // set memseq
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToReg(memseq, sr3));
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(sr3, sr2, offsetof(BufferEntry, memseq), true));
    //
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToRegaddrImm(
        memseq,
        sr2,
        offsetof(BufferEntry, memseq)));
}

// Fills a buffer entry for memop
void AddressStreamIntercept::instrumentMemop(
        BasicBlock* bb,
        X86Instruction* memop,
        uint8_t loadstoreflag,
        uint64_t blockSeq,
        uint32_t threadReg,
        SimulationStats& stats,
        uint32_t memopIdInBlock,
        uint32_t memopSeq){

    // First we build the actual instrumentation point
    InstrumentationSnippet* snip = addInstrumentationSnippet();
    InstrumentationPoint* pt = addInstrumentationPoint(memop, snip, InstrumentationMode_trampinline, InstLocation_prior);
    pt->setPriority(InstPriority_low);
    dynamicPoint(pt, GENERATE_KEY(blockSeq, PointType_bufferfill), true);

    // Then we fill the snippet with instructions

    // grab 3 scratch registers
    uint32_t sr1 = X86_REG_INVALID, sr2 = X86_REG_INVALID, sr3 = X86_REG_INVALID;
    // check if sr1 is already set for us
    if (threadReg != X86_REG_INVALID){
        sr1 = threadReg;
    }
    grabScratchRegisters(memop, InstLocation_prior, &sr1, &sr2, &sr3);
    ASSERT(sr1 != X86_REG_INVALID && sr2 != X86_REG_INVALID && sr3 != X86_REG_INVALID);

    // if thread data addr is not in sr1 already, load it
    // sr1 = stats
    if (threadReg == X86_REG_INVALID && usePIC()){
        Vector<X86Instruction*>* tdata = storeThreadData(sr2, sr1);
        for (uint32_t k = 0; k < tdata->size(); k++){
            snip->addSnippetInstruction((*tdata)[k]);
        }
        delete tdata;
    }

    ASSERT(memopIdInBlock < bb->getNumberOfMemoryOps() + bb->getNumberOfSWPrefetches()
);
    setupBufferEntry(snip, 1+memopIdInBlock-(bb->getNumberOfMemoryOps() + bb->getNumberOfSWPrefetches()), sr1, sr2, sr3, stats);
    if (loadstoreflag == PREFETCH) {
      writeBufferBase(snip, sr2, sr3, PREFETCH_ENTRY, LOAD, memopSeq);
    } else {
      writeBufferBase(snip, sr2, sr3, MEM_ENTRY, loadstoreflag, memopSeq);
    }

    // set address
    Vector<X86Instruction*>* addrStore = X86InstructionFactory64::emitAddressComputation(memop, sr3);
    while (!(*addrStore).empty()){
        snip->addSnippetInstruction((*addrStore).remove(0));
    }
    delete addrStore;
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(sr3, sr2, offsetof(BufferEntry, address), true));

    // Only for adamant
    //uint64_t programAddress = memop->getProgramAddress();
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToReg(programAddress, sr3));
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(sr3, sr2, offsetof(BufferEntry, programAddress), true));  

    // Only for debugging
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveThreadIdToReg(sr3));
    //snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(sr3, sr2, offsetof(BufferEntry, threadid), true));
}

void AddressStreamIntercept::grabScratchRegisters(
        X86Instruction* instRefPoint,
        InstLocations loc,
        uint32_t* sr1,
        uint32_t* sr2,
        uint32_t* sr3) {

    // start with all gpu regs except ax and sp
    BitSet<uint32_t>* inv = new BitSet<uint32_t>(X86_ALU_REGS);
    inv->insert(X86_REG_AX);
    inv->insert(X86_REG_SP);

    // invalidate presets TODO other regs
    if(sr1 && *sr1 != X86_REG_INVALID) {
       inv->insert(*sr1);
    }

    // invalidate any registers used by this instruction FIXME why?
    RegisterSet* regused = instRefPoint->getUnusableRegisters();
    for (uint32_t k = 0; k < X86_64BIT_GPRS; k++){
        if (regused->containsRegister(k)){
            inv->insert(k);
        }
    }
    delete regused;

    // Invalidate non-gprs FIXME just allocate a bitset without them
    for (uint32_t k = X86_64BIT_GPRS; k < X86_ALU_REGS; k++){
        inv->insert(k);
    }
    
    if (inv_reg) {
        inv->insert(get_reg());
    }

    // Look for dead registers in remaining valid
    BitSet<uint32_t>* dead = NULL;
    if(loc == InstLocation_prior)
        dead = instRefPoint->getDeadRegIn(inv, 3);
    else if(loc == InstLocation_after)
        dead = instRefPoint->getDeadRegOut(inv, 3);
    else
        assert(0 && "Invalid inst location");

    for (uint32_t k = 0; k < X86_64BIT_GPRS; k++){
        if (dead->contains(k)){
            if (sr1 && *sr1 == X86_REG_INVALID){
                *sr1 = k;
            } else if (sr2 && *sr2 == X86_REG_INVALID){
                *sr2 = k;
            } else if (sr3 && *sr3 == X86_REG_INVALID){
                *sr3 = k;
                break;
            }
        }
    }
    delete inv;
    delete dead;

}

void AddressStreamIntercept::setupBufferEntry(
        InstrumentationSnippet* snip,
        uint32_t bufferIdx,
        uint32_t sr1,
        uint32_t sr2,
        uint32_t sr3,
        SimulationStats& stats) {

    // sr2 = start of buffer
    if (usePIC()){
        // sr2 = ((SimulationStats*)sr1)->Buffer
        snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegaddrImmToReg(sr1, offsetof(SimulationStats, Buffer), sr2));
    } else {
        // sr2 = stats.Buffer
        snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToReg(getInstDataAddress() + (uint64_t)stats.Buffer, sr2));
    }

    // sr3 = ((BufferEntry*)sr2)->__buf_current;
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegaddrImmToReg(sr2, offsetof(BufferEntry, __buf_current), sr3));
    // sr3 = sr3 + sizeof(BuffestEntry)
    snip->addSnippetInstruction(X86InstructionFactory64::emitRegImmMultReg(sr3, sizeof(BufferEntry), sr3)); 
    // sr3 holds the offset (in bytes) of the access

    // sr2 = pointer to memop's buffer entry
    snip->addSnippetInstruction(X86InstructionFactory64::emitLoadEffectiveAddress(
        sr2, sr3, 1, sizeof(BufferEntry) * bufferIdx, sr2, true, true));

}


void AddressStreamIntercept::bufferVectorEntry(
        X86Instruction* instRefPoint,
        InstLocations   loc,
        X86Instruction* vectorIns,
        uint32_t        threadReg,
        SimulationStats& stats,
        uint32_t blockSeq,
        uint32_t memseq) {

    // First we build the actual instrumentation point
    InstrumentationSnippet* snip = addInstrumentationSnippet();
    InstrumentationPoint* point = addInstrumentationPoint(
        instRefPoint, snip, InstrumentationMode_trampinline, loc);
    point->setPriority(InstPriority_low);
    dynamicPoint(point, GENERATE_KEY(blockSeq, PointType_bufferfill), true);

    uint32_t sr1 = X86_REG_INVALID, sr2 = X86_REG_INVALID, sr3 = X86_REG_INVALID;
    if(threadReg != X86_REG_INVALID)
        sr1 = threadReg;
    grabScratchRegisters(instRefPoint, loc, &sr1, &sr2, &sr3);
    assert(sr1 != X86_REG_INVALID && sr2 != X86_REG_INVALID && sr3 != X86_REG_INVALID);

    // sr1 = stats
    if(threadReg == X86_REG_INVALID && usePIC()) {
        Vector<X86Instruction*>* insns = storeThreadData(sr2, sr1);
        for(uint32_t ins = 0; ins < insns->size(); ++ins) {
            snip->addSnippetInstruction((*insns)[ins]);
        }
        delete insns;
    }

    setupBufferEntry(snip, 0, sr1, sr2, sr3, stats);
    int8_t loadstoreflag;
    if(vectorIns->isLoad())
        loadstoreflag = LOAD;
    else if(vectorIns->isStore())
        loadstoreflag = STORE;
    else
        assert(0);
    writeBufferBase(snip, sr2, sr3, VECTOR_ENTRY, loadstoreflag, memseq);

    OperandX86* vectorOp = NULL;
    // vgatherdps (%r14,%zmm0,8), %zmm2 {k4}
    if(vectorIns->isLoad()) {
        Vector<OperandX86*>* ops = vectorIns->getSourceOperands();
        assert(ops->size() == 1);
        vectorOp = (*ops)[0];
        delete ops;
    } else if(vectorIns->isStore()) {
        vectorOp = vectorIns->getDestOperand();
        assert(vectorOp);
    } else assert(0);
    assert(vectorOp->getType() == UD_OP_MEM);

    uint32_t zmmReg  = vectorOp->getIndexRegister();
    uint32_t baseReg = vectorOp->getBaseRegister();
    uint8_t scale   = vectorOp->GET(scale);
    if(scale == 0) scale = 1;
    uint32_t kreg    = vectorIns->getVectorMaskRegister();
    uint32_t offset = vectorOp->getValue();

    // write base and/or offset
    if(baseReg != X86_REG_INVALID) {
        snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(
            baseReg,
            sr2,
            offsetof(BufferEntry, vectorAddress) + offsetof(VectorAddress, base),
            true));
        if(offset) {
            snip->addSnippetInstruction(X86InstructionFactory64::emitAddImmToRegaddrImm(
                offset,
                sr2,
                offsetof(BufferEntry, vectorAddress) + offsetof(VectorAddress, base)));
        }
    } else {
        snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToRegaddrImm(
            offset,
            sr2,
            offsetof(BufferEntry, vectorAddress) + offsetof(VectorAddress, base)));
    }

    // write scale
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveImmToRegaddrImm(
        scale,
        sizeof(scale),
        sr2,
        offsetof(BufferEntry, vectorAddress) + offsetof(VectorAddress, scale)));

    // write mask
    //   kmov k, sr3
    //   store sr3
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveKToReg(kreg, sr3));
    snip->addSnippetInstruction(X86InstructionFactory64::emitMoveRegToRegaddrImm(
        sr3,
        sr2,
        offsetof(BufferEntry, vectorAddress) + offsetof(VectorAddress, mask),
        true));

    // write index vector
    Vector<X86Instruction*>* insns = X86InstructionFactory64::emitUnalignedPackstoreRegaddrImm(
        zmmReg,
        X86_REG_K0,
        sr2,
        offsetof(BufferEntry, vectorAddress) + offsetof(VectorAddress, indexVector));

    for(int idx = 0; idx < insns->size(); ++idx) {
        snip->addSnippetInstruction((*insns)[idx]);
    }
    delete insns;

}

void AddressStreamIntercept::instrumentScatterGather(Loop* lp,
        uint32_t blockSeq,
        uint32_t memseq,
        uint32_t threadReg,
        SimulationStats& stats,
        Function* func,
        uint64_t noData,
        uint64_t simulationStruct
        )
{
    // instrument every source path to loop
    BasicBlock* head = lp->getHead();
    X86Instruction* vectorMemOp = head->getInstruction(0);

    Vector<BasicBlock*> entryInterpositions;
    uint32_t nsources = head->getNumberOfSources();
    for(int srci = 0; srci < nsources; ++srci) {
        BasicBlock* source = head->getSourceBlock(srci);
        if(lp->isBlockIn(source->getIndex()))
            continue;

        // fallthrough
        if(source->getBaseAddress() + source->getNumberOfBytes() == head->getBaseAddress()) {
            // instrument after exit instruction of source
            uint32_t numMemops = 1;
            insertBufferClear(numMemops, source->getExitInstruction(), InstLocation_after, blockSeq, threadReg, stats);
            
            // write a buffer entry for gather-scatter ops in loop
            bufferVectorEntry(source->getExitInstruction(), InstLocation_after, vectorMemOp, threadReg, stats, blockSeq, memseq);

        } else {
            entryInterpositions.append(source);
        }
    }
    FlowGraph* fg = head->getFlowGraph();
    for(int srci = 0; srci < entryInterpositions.size(); ++srci) {
        BasicBlock* source = entryInterpositions[srci];
        BasicBlock* interp = initInterposeBlock(fg, source->getIndex(), head->getIndex());
        // instrument before exit instruction of interp
        // TODO
    }

}

void AddressStreamIntercept::instrument(){
    // Required in every tool
    InstrumentationTool::instrument();

    // Initialize the blocksToInst vector (which blocks are we instrumenting?)
    initializeBlocksToInst();

    /*** TODO ACC --> Can this be moved? ***/
    if (dfpFile){
        PRINT_WARN(20, "--dfp is an accepted argument but it does nothing. "
          "range finding is done for every block included in the simulation "
          "by default");
    }

    // Sampling can be turned on and off in groups. Initialize those groups.
    initializeGroups();

    // Allocate space for null line info value
    allocateNullLineInfoValue();

    // Analyze code for thread registers
    std::set<Base*> functionsToInst;
    std::map<uint64_t, ThreadRegisterMap*>* functionThreading;
    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        Function* f = (Function*)bb->getLeader()->getContainer();
        functionsToInst.insert(f);
    }
    if (usePIC()){
        functionThreading = threadReadyCode(functionsToInst);
    }

    // Initialize SimulationStats, the data structure that will be passed
    // to the runtime library to help collect runtime info
    SimulationStats stats;
    initializeSimulationStats(stats);

    // Add arguments to instrumentation functions
    entryFunc->addArgument(getSimulationStatsOffset());
    entryFunc->addArgument(imageKey);
    entryFunc->addArgument(threadHash);
    memBufferFunc->addArgument(imageKey);
    exitFunc->addArgument(imageKey);

    instrumentEntryPoint();
    instrumentExitPoint();

    // TODO: remove all FP work from cache simulation?
    //memBufferFunc->assumeNoFunctionFP();

    // Begin instrumenting each block in the function
    uint64_t simulationStruct = getSimulationStatsOffset();
    uint32_t blockSeq = 0;
    uint32_t memopSeq = 0;
    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
        Function* func = (Function*)bb->getLeader()->getContainer();

        // Double-check that we want to instrument this block
        ASSERT((blocksToInstHash.get(bb->getHashCode().getValue())) && "Rogue "
          "block cound in blocksToInst array.");

        uint32_t threadReg = X86_REG_INVALID;
        if (usePIC()){
            ThreadRegisterMap* threadMap = (*functionThreading)[func->getBaseAddress()];
            threadReg = threadMap->getThreadRegister(bb);
        }

        // Check if block is part of gather-scatter loop
        // KNC only
        ASSERT((!(bb->getInstruction(0)->isScatterGatherOp())) && 
          "Address Stream Intercept found a scatter-gather block like "
          "that of KNC code. This code is deprecated.");

        uint32_t memopIdInBlock = 0;
        uint32_t leader = 0;
        for (uint32_t insIndex = 0; insIndex < bb->getNumberOfInstructions(); 
          insIndex++){
            X86Instruction* memop = bb->getInstruction(insIndex);

            // If this is the beginning of a new block, then we need to:
            //   1. Insert a counter for this block
            //   2. Insert runtime code to check to see if this block will
            //      overflow the buffer
            if (ifInstrumentingInstruction(memop) && ((memopIdInBlock == 0))){
                uint32_t counterSeq = blockSeq;
                if (isPerInstruction()){
                    counterSeq = memopSeq;
                } 
                    uint64_t counterOffset = (uint64_t)stats.Counters + 
                      (counterSeq * sizeof(uint64_t));
                    if (usePIC()) { 
                        counterOffset -= simulationStruct;
                    }
                    InstrumentationTool::insertBlockCounter(counterOffset, 
                      bb, true, threadReg);

                // TODO ACC: Get cleaner number of memops
                insertBufferClear(bb->getNumberOfMemoryOps() + 
                  bb->getNumberOfSWPrefetches(), memop, InstLocation_prior, 
                  blockSeq, threadReg, stats);

                leader = memopSeq;
            }

            // KNL implementation (not KNC)
            if (memop->isScatterGatherOp()) {
              bufferVectorEntry(memop, InstLocation_prior, memop, threadReg, 
                stats, blockSeq, memopSeq);
              ++memopIdInBlock;
              ++memopSeq;
            } else if (memop->isMemoryOperation()) {

                if(memop->isLoad()) {
                    instrumentMemop(bb, memop, LOAD, blockSeq, threadReg, 
                      stats, memopIdInBlock, memopSeq);
  
  
                    ++memopIdInBlock;
                    ++memopSeq;
                }
  
                if(memop->isStore()) {
                    instrumentMemop(bb, memop, STORE, blockSeq, threadReg, 
                      stats, memopIdInBlock, memopSeq);
  
  
  
                    ++memopIdInBlock;
                    ++memopSeq;
                } //store
            } //memop
            else if(memop->isSoftwarePrefetch()) {
                instrumentMemop(bb, memop, PREFETCH, blockSeq, threadReg, 
                  stats, memopIdInBlock, memopSeq);

                 ++memopIdInBlock;
                 ++memopSeq;
            }
        }
        blockSeq++;
    } // for each block


    if (usePIC()){
        delete functionThreading;
    }
    writeStaticFile();
    ASSERT(currentPhase == ElfInstPhase_user_reserve && "Instrumentation phase order must be observed"); 
}

void AddressStreamIntercept::writeStaticFile() {
    char* extension = new char[__MAX_STRING_SIZE];
    if (phaseNo > 0){
        sprintf(extension, "phase.1.%s", getExtension());
    } else {
        sprintf(extension, "%s", getExtension());
    }

    Vector<Base*> allBlocks;
    Vector<uint32_t> allBlockIds;
    Vector<LineInfo*> allBlockLineInfos;
    
    LineInfo* li = NULL;
    LineInfoFinder* lineInfoFinder = NULL;

    if (hasLineInformation()){
        lineInfoFinder = getLineInfoFinder();
    }

    for (uint32_t blockInd = 0; blockInd < blocksToInst.size(); blockInd++){
        BasicBlock* bb = blocksToInst[blockInd];
    //for(std::vector<BasicBlock*>::const_iterator it = blocksToInst.begin();
    //  it != blocksToInst.end(); it++) {
    //    BasicBlock* bb = (*it);
        Function* func = (Function*)bb->getLeader()->getContainer();

        // Check if we should skip this block
        if (!blocksToInstHash.get(bb->getHashCode().getValue()))
            continue;

        if (lineInfoFinder){
            li = lineInfoFinder->lookupLineInfo(bb);
        }

        // initialize block info
        if (!isPerInstruction()){
            allBlocks.append(bb);
            allBlockIds.append(blockInd);
            allBlockLineInfos.append(li);
        } else {
            for (uint32_t j = 0; j < bb->getNumberOfInstructions(); j++){
                X86Instruction* memop = bb->getInstruction(j);
                for (uint64_t m = 0; m < getNumberOfMemopsToInstrument(memop); 
                  m++) { 
                    allBlocks.append(memop);
                    allBlockIds.append(j);
                    allBlockLineInfos.append(li);
                }
            }
        }

    }
    

    if (isPerInstruction()){
        printStaticFilePerInstruction(extension, &allBlocks, &allBlockIds, &allBlockLineInfos, allBlocks.size());
    } else {
        printStaticFile(extension, &allBlocks, &allBlockIds, &allBlockLineInfos, allBlocks.size());
    }
    delete[] extension;
}

uint32_t AddressStreamIntercept::get_reg() {
    ASSERT(inv_reg);

    if (!strcmp(inv_reg, "r8")) {
        return X86_REG_R8;
    } else if (!strcmp(inv_reg, "r9")) {
        return X86_REG_R9;
    } else if (!strcmp(inv_reg, "r10")) {
        return X86_REG_R10;
    } else if (!strcmp(inv_reg, "r11")) {
        return X86_REG_R11;
    } else if (!strcmp(inv_reg, "r12")) {
        return X86_REG_R12;
    } else if (!strcmp(inv_reg, "r13")) {
        return X86_REG_R13;
    } else if (!strcmp(inv_reg, "r14")) {
        return X86_REG_R14;
    } else if (!strcmp(inv_reg, "r15")) {
        return X86_REG_R15;
    } else if (!strcmp(inv_reg, "ax")) {
        return X86_REG_AX;
    } else if (!strcmp(inv_reg, "bx")) {
        return X86_REG_BX;
    } else if (!strcmp(inv_reg, "cx")) {
        return X86_REG_CX;
    } else if (!strcmp(inv_reg, "dx")) {
        return X86_REG_DX;
    } else if (!strcmp(inv_reg, "sp")) {
        return X86_REG_SP;
    } else if (!strcmp(inv_reg, "bp")) {
        return X86_REG_BP;
    } else if (!strcmp(inv_reg, "si")) {
        return X86_REG_SI;
    } else if (!strcmp(inv_reg, "di")) {
        return X86_REG_DI;
    } else {
        return X86_REG_INVALID;
    }
}
