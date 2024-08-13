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
#include <ArielIntercept.h>

#include <BasicBlock.h>
#include <Function.h>
#include <Instrumentation.h>
#include <X86Instruction.h>
#include <X86InstructionFactory.h>
#include <LineInformation.h>
#include <Loop.h>
#include <TextSection.h>

extern "C" {
    InstrumentationTool* ArielInterceptMaker(ElfFile* elf){
        return new ArielIntercept(elf);
    }
}

// Insert instrumentation to collect data about the number of instructions
// executed before this memory instruction
// I.e., fill and INSN_COUNT buffer entry
void ArielIntercept::collectInsnCountEntry(BasicBlock* bb, X86Instruction*
  memop, uint32_t threadReg, AddressStreamStats& stats, uint64_t blockSeq,
  uint64_t& numNonMemops, uint64_t bufferIndex) {

    // Note: Even if there are no non memops, we still need to insert a buffer
    // entry because we moved the pointer to __buf_current in insertBufferClear

    // First we build the actual instrumentation point
    InstrumentationSnippet* snip = addInstrumentationSnippet();
    InstrumentationPoint* pt = addInstrumentationPoint(memop, snip, 
      InstrumentationMode_trampinline, InstLocation_prior);
    pt->setPriority(InstPriority_low);
    dynamicPoint(pt, GENERATE_UNIQUE_KEY(blockSeq, 0, PointType_bufferfill), 
      true);

    // Then we fill the snippet with instructions
    // Code requires three scratch registers so grab 3
    uint32_t sr1 = X86_REG_INVALID;  // thread register
    uint32_t sr2 = X86_REG_INVALID;
    uint32_t sr3 = X86_REG_INVALID;

    // check if sr1 is already set for us
    if (threadReg != X86_REG_INVALID){
        sr1 = threadReg;
    }
    grabScratchRegisters(memop, InstLocation_prior, &sr1, &sr2, &sr3);
    ASSERT(sr1 != X86_REG_INVALID && sr2 != X86_REG_INVALID && 
      sr3 != X86_REG_INVALID);

    // if thread data addr is not in sr1 already, load it
    // sr1 = stats
    if (threadReg == X86_REG_INVALID && usePIC()){
        Vector<X86Instruction*>* tdata = storeThreadData(sr2, sr1);
        for (uint32_t k = 0; k < tdata->size(); k++){
            snip->addSnippetInstruction((*tdata)[k]);
        }
        delete tdata;
    }

    // Set sr2 to point to the location of our buffer entry. For performance,
    // we already have increased __buf_current. We set __buf_oldPosition to
    // be where __buf_current was before the increase. This makes assembly 
    // a little easier and makes threading (with ProcessAllBuffers) possible
    setSr2ToBufferEntry(stats, snip, sr1, sr2, sr3, bufferIndex + 1);

    // Fill memopSeq, prefetch flag, and load store flag with 0s. They
    // shouldn't be used
    writeBufferEntry(snip, 0, sr2, sr3, numNonMemops, INSN_COUNT, 0, 0);

//    // Update the buffer index
//    bufferIndex++;
}

// Get the number of buffer elements that will be inserted in this block
uint64_t ArielIntercept::getNumberOfBufferElements(BasicBlock* bb) {
    uint64_t numEntries = 0;
    // The number of buffer entries is:
    // the number of memory instructions (for the insn count)
    // +
    // the number of memopry operations (to the address collection)
    // +
    // 1 (for the buffer entry for the end of the block)
//    for (auto i = 0; i < bb->getNumberOfInstructions(); i++) {
//        X86Instruction* memop = bb->getInstruction(i);
//        if (getNumberOfMemopsToInstrument(memop) > 0)
//            numEntries++;
//    }

    numEntries += getNumberOfMemopsToInstrument(bb);
    numEntries += 1;
    return numEntries;
}
