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

#ifndef _AddressStreamIntercept_h_
#define _AddressStreamIntercept_h_

#include <InstrumentationTool.h>
#include <SimpleHash.h>
#include <Vector.h>
#include <AddressStreamStats.hpp>


class AddressStreamIntercept : public InstrumentationTool {
private:
    InstrumentationFunction* memBufferFunc;
    InstrumentationFunction* exitFunc;
    InstrumentationFunction* entryFunc;

    SimpleHash<BasicBlock*> blocksToInstHash;   // <hash, BB*>
    Vector<BasicBlock*> blocksToInst;      // All BBs to instrument
                                           // Should probably be kept sorted

    SimpleHash<uint64_t> mapBBToGroupId;  // <hash, GroupId>

    bool includeLoads = true;
    bool includeStores = true;
    bool includeSWPrefetches = true;

    uint64_t nullLineInfoValue = 0;
    uint64_t simulationStatsOffset = 0;

    void allocateNullLineInfoValue();
    void allocateSimulationStats(uint64_t);

    uint64_t getNullLineInfoValue();
    uint32_t getNumberOfBlocksToInstrument();
    uint64_t getNumberOfGroups();
    uint32_t getNumberOfMemopsToInstrument();
    uint64_t getNumberOfMemopsToInstrument(X86Instruction*);
    uint64_t getSimulationStatsOffset();

    bool ifInstrumentingInstruction(X86Instruction*);
    bool ifInstrumentingLoads() { return includeLoads; }
    bool ifInstrumentingStores() { return includeStores; }
    bool ifInstrumentingSWPrefetches() { return includeSWPrefetches; }

    void initializeBlocksToInst();
    void initializeFirstBufferEntry(BufferEntry&);
    void initializeGroups();
    void initializeSimulationStats(SimulationStats&);
    
    void instrumentEntryPoint();
    void instrumentExitPoint();

//    Vector<Base*> allBlocks;
 //   Vector<uint32_t> allBlockIds;
//    Vector<LineInfo*> allBlockLineInfos;


    void includeLoopBlocks(BasicBlock*);
    void grabScratchRegisters(X86Instruction*,InstLocations,uint32_t*,uint32_t*,uint32_t*);

    void initializeInstructionInfo(X86Instruction*,uint32_t,SimulationStats&,
      Function*,BasicBlock*,uint32_t,uint32_t,uint32_t,uint32_t,uint64_t,
      uint64_t,uint64_t, uint32_t*);
    void initializeBlockInfo(BasicBlock*,SimulationStats&,Function*,uint32_t,uint64_t,uint32_t*);

    void setupBufferEntry(InstrumentationSnippet*,uint32_t,uint32_t,uint32_t,uint32_t, SimulationStats&);
    void writeBufferBase(InstrumentationSnippet*,uint32_t,uint32_t,enum EntryType, uint8_t,uint32_t);
    void insertBufferClear(uint32_t,X86Instruction*,InstLocations,uint64_t,uint32_t,SimulationStats&);
    void bufferVectorEntry(X86Instruction*,InstLocations,X86Instruction*,uint32_t,SimulationStats&,uint32_t,uint32_t);
    void instrumentScatterGather(Loop*, uint32_t,uint32_t,uint32_t,
      SimulationStats&,Function*,uint64_t,uint64_t,uint32_t*);
    void instrumentMemop(BasicBlock*,X86Instruction*,uint8_t,uint64_t,uint32_t,SimulationStats&,uint32_t,uint32_t);
    void initializeLineInfo(SimulationStats&, Function*, BasicBlock*, uint32_t, uint64_t);
    void writeStaticFile();

    uint32_t get_reg();

    inline bool usePIC() { return isThreadedMode() || isMultiImage(); }
public:
    AddressStreamIntercept(ElfFile* elf);
    ~AddressStreamIntercept();

    void declare();
    void instrument();

    const char* briefName() { return "AddressStreamIntercept"; }
    const char* defaultExtension() { return "addstrinst"; }
    uint32_t allowsArgs() { return PEBIL_OPT_LPI | PEBIL_OPT_DTL | PEBIL_OPT_PHS | PEBIL_OPT_DFP; }
    uint32_t requiresArgs() { return PEBIL_OPT_INP; }
};


#endif /* _AddressStreamIntercept_h_ */
