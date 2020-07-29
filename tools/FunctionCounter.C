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
#include <FunctionCounter.h>

#include <BasicBlock.h>
#include <Function.h>
#include <LineInformation.h>

extern "C" {
    InstrumentationTool* FunctionCounterMaker(ElfFile* elf){
        return new FunctionCounter(elf);
    }
}

uint32_t FunctionCounter::getNumberOfBlocksToInstrument() {
    return getNumberOfExposedFunctions();
}

void FunctionCounter::setBlocksToInstrument() {
    for (uint32_t i = 0; i < getNumberOfBlocksToInstrument(); i++) {
        Function* f = getExposedFunction(i);
        BasicBlock* bb = f->getFlowGraph()->getEntryBlock();

        LineInfo* li = NULL;
        if (lineInfoFinder) {
            li = lineInfoFinder->lookupLineInfo(bb);
        }

        allAddresses->append(bb->getProgramAddress());
        allBlocks->append(bb);
        allBlockIds->append(i);
        allBlockLineInfos->append(li);
        allFunctions->append(f);
        allHashes->append(bb->getHashCode().getValue());
    }
}

