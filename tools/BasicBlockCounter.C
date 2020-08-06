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

#include <BasicBlockCounter.h>

#include <BasicBlock.h>
#include <Function.h>
#include <X86Instruction.h>
#include <X86InstructionFactory.h>
#include <LineInformation.h>
#include <Loop.h>

#include <CounterFunctions.hpp>

#include <map>

#define ENTRY_FUNCTION "tool_image_init"
#define EXIT_FUNCTION "tool_image_fini"
#define INST_LIB_NAME "libcounter.so"
#define NOSTRING "__pebil_no_string__"

extern "C" {
    InstrumentationTool* BasicBlockCounterMaker(ElfFile* elf) {
        return new BasicBlockCounter(elf);
    }
}


/* Protected Functions */
uint32_t BasicBlockCounter::getNumberOfBlocksToInstrument() {

    if (isPerInstruction()) {
        PRINT_INFOR("Performing instrumentation to gather PER-INSTRUCTION \
          statistics");
        return getNumberOfExposedInstructions();
    }

    return getNumberOfExposedBasicBlocks();
}

void BasicBlockCounter::setBlocksToInstrument() {
    for (uint32_t i = 0; i < getNumberOfBlocksToInstrument(); i++) {
        LineInfo* li = NULL;
        Function* f = NULL;
        BasicBlock* bb = NULL;
        uint64_t hashValue;

        // Collect all instructions
        if (isPerInstruction()) {
            X86Instruction* ins = getExposedInstruction(i);

            if (lineInfoFinder){
                li = lineInfoFinder->lookupLineInfo(ins);
            }
            f = (Function*)ins->getContainer();
            bb = f->getBasicBlockAtAddress(ins->getBaseAddress());
            ASSERT(bb && "exposed instruction should be in a basic block");

            allAddresses->append(ins->getProgramAddress());
            allBlocks->append(ins);
            allBlockIds->append(i);
            allBlockLineInfos->append(li);
            allFunctions->append(f);
            HashCode* hc = ins->generateHashCode(bb);
            allHashes->append(hc->getValue());
            delete hc;
        // Collect all blocks
        } else {
            bb = getExposedBasicBlock(i);
            if (lineInfoFinder){
                li = lineInfoFinder->lookupLineInfo(bb);
            }
            f = bb->getFunction();
            
            allAddresses->append(bb->getProgramAddress());
            allBlocks->append(bb);
            allBlockIds->append(i);
            allBlockLineInfos->append(li);
            allFunctions->append(f);
            allHashes->append(bb->getHashCode().getValue());
        }
    }
}

void BasicBlockCounter::setLineInfoFinder() {
    if (hasLineInformation()){
        lineInfoFinder = getLineInfoFinder();
    }
}

void BasicBlockCounter::setLoopsToInstrument() {
    // Skip if not instrumenting loops
    if (!isInstrumentingLoops())
        return;

    // Search for loops and populate loopsToInstrument
    for (uint32_t i = 0; i < getNumberOfExposedBasicBlocks(); i++){
        BasicBlock* bb = getExposedBasicBlock(i);

        if (bb->isInLoop()){
            FlowGraph* fg = bb->getFlowGraph();
            Loop* outerMost = fg->getInnermostLoopForBlock(bb->getIndex());

            bool loopAlreadyInstrumented = false;
            for (uint32_t i = 0; i < loopsToInstrument->size(); i++){
                if (outerMost->isIdenticalLoop((*loopsToInstrument)[i])){
                    loopAlreadyInstrumented = true;
                }
            }
            if (!loopAlreadyInstrumented && loopCount){
                loopsToInstrument->append(outerMost);
            }
        }
    }
}

/* Public Functions */
BasicBlockCounter::BasicBlockCounter(ElfFile* elf)
    : InstrumentationTool(elf) {
    entryFunc = NULL;
    exitFunc = NULL;


    allAddresses = new Vector<uint64_t>();
    allBlocks = new Vector<Base*>();
    allBlockIds = new Vector<uint32_t>();
    allBlockLineInfos = new Vector<LineInfo*>();
    allFunctions = new Vector<Function*>();
    allHashes = new Vector<uint64_t>();
    loopCount = true;
    loopsToInstrument = new Vector<Loop*>();
}

BasicBlockCounter::~BasicBlockCounter() {
    delete allAddresses;
    delete allBlocks;
    delete allBlockIds;
    delete allBlockLineInfos;
    delete allFunctions;
    delete allHashes;
    delete loopsToInstrument;
}

void BasicBlockCounter::declare() {
    InstrumentationTool::declare();
    ASSERT(currentPhase == ElfInstPhase_user_declare && 
      "Instrumentation phase order must be observed"); 
    
    // declare any shared library that will contain instrumentation functions
    declareLibrary(INST_LIB_NAME);

    // declare any instrumentation functions that will be used
    exitFunc = declareFunction(EXIT_FUNCTION);
    ASSERT(exitFunc && "Cannot find exit function, are you sure it was "
      "declared?");

    entryFunc = declareFunction(ENTRY_FUNCTION);
    ASSERT(entryFunc && "Cannot find entry function, are you sure it was "
      "declared?");

    ASSERT(currentPhase == ElfInstPhase_user_declare && 
      "Instrumentation phase order must be observed"); 
}

void BasicBlockCounter::instrument() {
    // First set up tool
    InstrumentationTool::instrument();
    ASSERT(currentPhase == ElfInstPhase_user_reserve && 
      "Instrumentation phase order must be observed"); 

    // Create and initialize the CounterArray data structure
    CounterArray ctrs;
    ctrs.Initialized = true;
    ctrs.PerInstruction = isPerInstruction();
    ctrs.Master = isMasterImage();

    // Get all the points we will instrument (Size)
    // Get all the loops we will instrument
    setLoopsToInstrument();
    uint32_t numberOfBlocks = getNumberOfBlocksToInstrument();
    uint32_t numberOfPoints = numberOfBlocks + loopsToInstrument->size();
    ctrs.Size = numberOfPoints;

    // Reserve data and pointers to per-block data
    uint64_t counterStruct = reserveDataOffset(sizeof(CounterArray));
#define INIT_CTR_ELEMENT(__typ, __nam)\
    ctrs.__nam = (__typ*)reserveDataOffset(numberOfPoints * sizeof(__typ));\
    initializeReservedPointer((uint64_t)ctrs.__nam, counterStruct +\
    offsetof(CounterArray, __nam))

    INIT_CTR_ELEMENT(uint64_t, Counters);
    INIT_CTR_ELEMENT(CounterTypes, Types);
    INIT_CTR_ELEMENT(uint32_t, BlockIds);
    INIT_CTR_ELEMENT(uint64_t, Addresses);
    INIT_CTR_ELEMENT(uint64_t, Hashes);
    INIT_CTR_ELEMENT(uint32_t, Lines);
    INIT_CTR_ELEMENT(char*, Files);
    INIT_CTR_ELEMENT(char*, Functions);

    // Reserve and set Application and Extenstion pointers
    char* appName = getElfFile()->getAppName();
    uint64_t app = reserveDataOffset(strlen(appName) + 1);
    initializeReservedPointer(app, counterStruct + offsetof(CounterArray, 
      Application));
    initializeReservedData(getInstDataAddress() + app, strlen(appName) + 1, 
      (void*)appName);

    char extName[__MAX_STRING_SIZE];
    sprintf(extName, "%s\0", getExtension());
    uint64_t ext = reserveDataOffset(strlen(extName) + 1);
    initializeReservedPointer(ext, counterStruct + offsetof(CounterArray, 
      Extension));
    initializeReservedData(getInstDataAddress() + ext, strlen(extName) + 1, 
      (void*)extName);

    // Write our Counter Array data structure
    initializeReservedData(getInstDataAddress() + counterStruct, 
      sizeof(CounterArray), (void*)(&ctrs));

    // Start instrumenting
    // Instrument exit block for image
    exitFunc->addArgument(imageKey);
    InstrumentationPoint* p = addInstrumentationPoint(getProgramExitBlock(), 
      exitFunc, InstrumentationMode_tramp, InstLocation_prior);
    if (!p->getInstBaseAddress()) {
        PRINT_ERROR("Cannot find an instrumentation point at the exit "
          "function");
    }

    // Instrument entry points for image
    entryFunc->addArgument(counterStruct);
    entryFunc->addArgument(imageKey);
    entryFunc->addArgument(threadHash);
    if (isMultiImage()) {
        for (uint32_t i = 0; i < getNumberOfExposedFunctions(); i++){
            Function* f = getExposedFunction(i);

            p = addInstrumentationPoint(f, entryFunc, InstrumentationMode_tramp,
              InstLocation_prior);
            p->setPriority(InstPriority_userinit);
            if (!p->getInstBaseAddress()) {
                PRINT_ERROR("Cannot find an instrumentation point at the entry "
                  "block");
            }
            dynamicPoint(p, getElfFile()->getUniqueId(), true);
        }
    } else {
        p = addInstrumentationPoint(getProgramEntryBlock(), entryFunc, 
          InstrumentationMode_tramp, InstLocation_prior);
        p->setPriority(InstPriority_userinit);
        if (!p->getInstBaseAddress()) {
            PRINT_ERROR("Cannot find an instrumentation point at the entry "
              "block");
        }
    }

    // Set up threading
    std::set<Base*> functionsToInst;
    for (uint32_t i = 0; i < getNumberOfExposedFunctions(); i++){
        functionsToInst.insert(getExposedFunction(i));
    }
    bool usePIC = false;
    if (isThreadedMode() || isMultiImage()){
        usePIC = true;
    }
    std::map<uint64_t, ThreadRegisterMap*>* functionThreading;
    if (usePIC){
        functionThreading = threadReadyCode(functionsToInst);
    }
    functionsToInst.clear();

    // Fill out per-block data and then instrument each block!
    // First set up variables that we will need
    uint32_t temp32;
    uint64_t temp64;
    uint64_t currentLeader = 0;
    setLineInfoFinder();
    setBlocksToInstrument();

    // Set up a place for the string that says we can't find the line
    uint64_t noData = reserveDataOffset(strlen(NOSTRING) + 1);
    char* nostring = new char[strlen(NOSTRING) + 1];
    sprintf(nostring, "%s\0", NOSTRING);
    initializeReservedData(getInstDataAddress() + noData, strlen(NOSTRING) + 1,
      nostring);

    // iterate over each block/instruction
    // block mode inserts a counter at each block
    // instruction mode inserts a counter at each block and initializes a 
    // leader reference for each instruction
    for (uint32_t i = 0; i < allBlocks->size(); i++) {

        // First, set our current block/instruction
        X86Instruction* ins = NULL;
        BasicBlock* bb = NULL;
        Function* f = (*allFunctions)[i];

        if (isPerInstruction()) {
            ins = (X86Instruction*)(*allBlocks)[i];
            bb = f->getBasicBlockAtAddress(ins->getBaseAddress());
        } else {
            ins = NULL;
            bb = (BasicBlock*)(*allBlocks)[i];
        }
        ASSERT(f && bb);
        if (isPerInstruction()){
            ASSERT(ins);
        }

        // Counters and Types (do with instrumentation at bottom of loop)
        // Addresses and Hashes
        uint64_t addr = (*allAddresses)[i];
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Addresses 
          + i*sizeof(uint64_t), sizeof(uint64_t), &addr);
        
        uint64_t hashValue = (*allHashes)[i];
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Hashes + 
          i*sizeof(uint64_t), sizeof(uint64_t), &hashValue);
        
        // Lines and Files
        LineInfo* li = (*allBlockLineInfos)[i];
        // populate these only if we have the info
        if (li) {
            uint32_t line = li->GET(lr_line);
            initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Lines 
              + sizeof(uint32_t)*i, sizeof(uint32_t), &line);

            uint64_t filename = reserveDataOffset(strlen(li->getFileName()) 
              + 1);
            initializeReservedPointer(filename, (uint64_t)ctrs.Files + 
              i*sizeof(char*));
            initializeReservedData(getInstDataAddress() + filename, 
              strlen(li->getFileName()) + 1, (void*)li->getFileName());
        // if no line info, just put 0
        } else {
            temp32 = 0;
            initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Lines 
              + sizeof(uint32_t)*i, sizeof(uint32_t), &temp32);
            initializeReservedPointer(noData, (uint64_t)ctrs.Files + 
              i*sizeof(char*));
        }

        // BlockIds
        uint32_t checkBlockId = (*allBlockIds)[i];
        ASSERT(checkBlockId == i && "Error with setting up blocks to "
          "instrument")
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.BlockIds +
          sizeof(uint32_t)*i, sizeof(uint32_t), &i);

        // Functions
        uint64_t funcname = reserveDataOffset(strlen(f->getName()) + 1);
        initializeReservedPointer(funcname, (uint64_t)ctrs.Functions + 
          i*sizeof(char*));
        initializeReservedData(getInstDataAddress() + funcname, 
          strlen(f->getName()) + 1, (void*)f->getName());

        // Counters and Types
        // For insns, they get type instruction. Blocks (and first insn in 
        // blocks) get type Block
        // Initialize counter data for non-leader instruction counters
        CounterTypes tmpct;
        if (isPerInstruction()) {
            // only keep a bb counter for one instruction in the block 
            // (the leader). all other instructions' counters hold the ID of 
            // the active counter in their block
            if (bb->getLeader()->getBaseAddress() != ins->getBaseAddress()){
                tmpct = CounterType_instruction;
                initializeReservedData(getInstDataAddress() + 
                  (uint64_t)ctrs.Types + i*sizeof(CounterTypes), 
                  sizeof(CounterTypes), &tmpct);        
                
                temp64 = currentLeader;
                initializeReservedData(getInstDataAddress() + 
                  (uint64_t)ctrs.Counters + (i * sizeof(uint64_t)), 
                  sizeof(uint64_t), &temp64);
               
                // Not instrumenting here so skip
                continue;
            }
        }

        // other wise, for leader instructions
        // reset leader
        currentLeader = i;

        // Set the correct Counter and Type
        tmpct = CounterType_basicblock;
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Types + 
          i*sizeof(CounterTypes), sizeof(CounterTypes), &tmpct);        

        // Initialize count to 0
        temp64 = 0;
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Counters + 
          (i * sizeof(uint64_t)), sizeof(uint64_t), &temp64);

        uint64_t counterOffset = (uint64_t)ctrs.Counters + (i * 
          sizeof(uint64_t));
        uint32_t threadReg = X86_REG_INVALID;

        if (usePIC){
            counterOffset -= (uint64_t)ctrs.Counters;
            ThreadRegisterMap* threadMap = (*functionThreading)[f->
              getBaseAddress()];
            threadReg = threadMap->getThreadRegister(bb);
        }

        if (isSaveAll() && isThreadedMode()) threadReg = X86_REG_INVALID;

        // Instrument!
        InstrumentationTool::insertBlockCounter(counterOffset, bb, true, 
          threadReg);
    }

    // Next, instrument loops. If "isInstrumentingLoops" is false, then 
    // there shouldn't be any loops in the loops to instrument structure
    if (isInstrumentingLoops())
        PRINT_INFOR("Instrumenting %d loops for counting", 
          loopsToInstrument->size());
    for (uint32_t loopNumber = 0; loopNumber < loopsToInstrument->size();
      loopNumber++) {
        // Double-check that we should be here
        ASSERT(isInstrumentingLoops() && "Found loops to instrument but not "
          "instrumenting loops!");

        // Get our loop and function information
        Loop* loop = (*loopsToInstrument)[loopNumber];
        BasicBlock* head = loop->getHead();
        BasicBlock* tail = loop->getTail();
        Function* f = head->getFunction();
        ASSERT(head && tail);

        // Set up per-block data
        // First need the index into the per-block data
        uint32_t i = numberOfBlocks + loopNumber;
        ASSERT(i < numberOfPoints && "Did not allocate room for this loop");

        // Counters and Types - do at bottom of loop with instrumentation 
        // Addresses and Hashes
        uint64_t addr = head->getProgramAddress();
        uint64_t hashValue = head->getHashCode().getValue();

        if (isPerInstruction()){
            X86Instruction* ins = head->getLeader();
            HashCode* hc = ins->generateHashCode(head);
            hashValue = hc->getValue();
            addr = ins->getProgramAddress();
            delete hc;
        }
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Addresses +
          i*sizeof(uint64_t), sizeof(uint64_t), &addr);
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Hashes + 
          i*sizeof(uint64_t), sizeof(uint64_t), &hashValue);

        // Lines and Files
        LineInfo* li = NULL;
        if (lineInfoFinder) {
            li = lineInfoFinder->lookupLineInfo(head);
        }
        // populate these only if we have the info
        if (li) {
            uint32_t line = li->GET(lr_line);
            initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Lines +
              sizeof(uint32_t)*i, sizeof(uint32_t), &line);

            uint64_t filename = reserveDataOffset(strlen(li->getFileName()) 
              + 1);
            initializeReservedPointer(filename, (uint64_t)ctrs.Files + 
              i*sizeof(char*));
            initializeReservedData(getInstDataAddress() + filename, 
              strlen(li->getFileName()) + 1, (void*)li->getFileName());
        // if no line info, just put 0
        } else {
            temp32 = 0;
            initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Lines +
              sizeof(uint32_t)*i, sizeof(uint32_t), &temp32);
            initializeReservedPointer(noData, (uint64_t)ctrs.Files + 
              i*sizeof(char*));
        }

        // BlockIds
        uint32_t loopId = loop->getIndex();
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.BlockIds +
          sizeof(uint32_t)*i, sizeof(uint32_t), &loopId);

        // Functions
        uint64_t funcname = reserveDataOffset(strlen(f->getName()) + 1);
        initializeReservedPointer(funcname, (uint64_t)ctrs.Functions + 
          i*sizeof(char*));
        initializeReservedData(getInstDataAddress() + funcname, 
          strlen(f->getName()) + 1, (void*)f->getName());

        // Counters and Types
        uint64_t counterOffset =  (uint64_t)ctrs.Counters + (i * 
          sizeof(uint64_t));
        uint32_t threadReg = X86_REG_INVALID;
        if (usePIC){
            counterOffset -= (uint64_t)ctrs.Counters;
            ThreadRegisterMap* threadMap = (*functionThreading)[f->
              getBaseAddress()];
            threadReg = threadMap->getThreadRegister(head);
        }
        if (isSaveAll() && isThreadedMode()) threadReg = X86_REG_INVALID;

        CounterTypes tmpct = CounterType_loop;
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Types + 
          i*sizeof(CounterTypes), sizeof(CounterTypes), &tmpct);

        // Initialize count to 0
        temp64 = 0;
        initializeReservedData(getInstDataAddress() + (uint64_t)ctrs.Counters + 
          (i * sizeof(uint64_t)), sizeof(uint64_t), &temp64);

        // Instrument!
        // increment counter on each time we encounter the loop head
        InstrumentationTool::insertBlockCounter(counterOffset, head, true, 
          threadReg);

        // decrement counter each time we traverse a back edge
        for (uint32_t j = 0; j < tail->getNumberOfTargets(); j++) {
            BasicBlock* target = tail->getTargetBlock(j);
            FlowGraph* fg = target->getFlowGraph();
            if (head->getHashCode().getValue() == 
              target->getHashCode().getValue()) {
                ASSERT(head->getHashCode().getValue() == 
                  target->getHashCode().getValue());

                // if control falls from tail to head, stick a decrement at 
                // the very end of the block
                if (tail->getBaseAddress() + tail->getNumberOfBytes() == 
                  target->getBaseAddress()) {
                    InstrumentationTool::insertInlinedTripCounter(counterOffset,
                      tail->getExitInstruction(), false, threadReg, 
                      InstLocation_after, NULL, 1);
                } else {
                    BasicBlock* interposed = initInterposeBlock(fg, 
                      tail->getIndex(), target->getIndex());
                    InstrumentationTool::insertInlinedTripCounter(counterOffset,
                      interposed->getLeader(), false, threadReg, 
                      InstLocation_prior, NULL, 1);
                }
            }
        }
    }

    if (isPerInstruction()){
        printStaticFilePerInstruction(getExtension(), allBlocks, allBlockIds, 
          allBlockLineInfos, allBlocks->size());
    } else {
        printStaticFile(getExtension(), allBlocks, allBlockIds, 
          allBlockLineInfos, allBlocks->size());
        printCallTreeInfo(getExtension(), allBlocks, allBlockIds, 
          allBlockLineInfos, allBlocks->size());
    }

    delete[] nostring;

    if (usePIC){
        delete functionThreading;
    }

    ASSERT(currentPhase == ElfInstPhase_user_reserve && "Instrumentation phase "
      "order must be observed"); 
}
