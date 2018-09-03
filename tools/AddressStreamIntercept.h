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
    // Runtime Library Functions
    InstrumentationFunction* memBufferFunc;
    InstrumentationFunction* exitFunc;
    InstrumentationFunction* entryFunc;

    // Useful data structures
    SimpleHash<BasicBlock*> blocksToInstHash;   // <hash, BB*>
    Vector<BasicBlock*> blocksToInst;      // All BBs to instrument
                                           // Should probably be kept sorted

    SimpleHash<uint64_t> mapBBToGroupId;  // <hash, GroupId>

    // Bools to control which memops are instrumented    
    bool includeLoads = true;
    bool includeStores = true;
    bool includeSWPrefetches = false;

    // Helpful variables for initializing data structures
    uint64_t nullLineInfoValue = 0;
    uint64_t simulationStatsOffset = 0;

    // Functions to allocate space in the instrumented binary
    void allocateNullLineInfoValue();
    void allocateAddressStreamStats(uint64_t);

    // Functions to create different kinds of memops
    void collectMemEntry(BasicBlock*, X86Instruction*, uint32_t, 
      AddressStreamStats&, uint32_t, uint32_t, uint32_t, uint8_t);

    uint64_t getNullLineInfoValue();
    uint32_t getNumberOfBlocksToInstrument();
    uint64_t getNumberOfGroups();
    uint64_t getNumberOfMemopsToInstrument();
    uint64_t getNumberOfMemopsToInstrument(BasicBlock*);
    uint64_t getNumberOfMemopsToInstrument(X86Instruction*);
    uint32_t getOffLimitsRegister();
    uint64_t getAddressStreamStatsOffset();

    bool ifInstrumentingInstruction(X86Instruction*);
    bool ifInstrumentingLoads() { return includeLoads; }
    bool ifInstrumentingStores() { return includeStores; }
    bool ifInstrumentingSWPrefetches() { return includeSWPrefetches; }

    // Functions to initialize data in instrumented binary
    void initializeBlocksToInst();
    void initializeFirstBufferEntry(BufferEntry&);
    void initializeGroups();
    void initializePerBlockData(AddressStreamStats&);
    void initializePerGroupData(AddressStreamStats&);
    void initializePerMemopData(AddressStreamStats&);
    void initializeAddressStreamStats(AddressStreamStats&);
 
    // Functions to insert instrumentation   
    void insertBufferClear(X86Instruction*, InstLocations, uint32_t, 
      AddressStreamStats&, uint64_t, uint32_t);
    void insertAddressCollection(BasicBlock*, X86Instruction*, uint32_t,
      AddressStreamStats&, uint32_t, uint32_t, uint32_t);
    void instrumentEntryPoint();
    void instrumentExitPoint();

    // Common methods for instrumentation functions
    void grabScratchRegisters(X86Instruction*, InstLocations, uint32_t*,
      uint32_t*, uint32_t*);
    void setSr2ToBufferEntry(AddressStreamStats&, InstrumentationSnippet*, 
      uint32_t, uint32_t, uint32_t, int32_t);
    inline bool usePIC() { return isThreadedMode() || isMultiImage(); }
    void writeBufferEntry(InstrumentationSnippet*, uint32_t, uint32_t, uint32_t,
      enum EntryType, uint8_t);

    void writeStaticFile();

    // To be used later
    //  void bufferVectorEntry(X86Instruction*,InstLocations,X86Instruction*,uint32_t,AddressStreamStats&,uint32_t,uint32_t);
    void initializeLineInfo(AddressStreamStats&, Function*, BasicBlock*, uint32_t, uint64_t);


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
