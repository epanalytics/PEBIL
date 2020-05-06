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

#ifndef _Loop_h_
#define _Loop_h_

#include <Base.h>
#include <BitSet.h>
#include <Function.h>

extern int compareLoopEntry(const void* arg1,const void* arg2);

class Loop : public Base {
protected:
    uint32_t index;
    FlowGraph* flowGraph;
    BitSet<BasicBlock*>* blocks;
    BasicBlock* head;
    BasicBlock* tail;

    uint32_t depth;
public:
    Loop(BasicBlock* h, BasicBlock* t, FlowGraph* cfg, BitSet<BasicBlock*>* newBlocks);
    Loop(const Loop &l);
    ~Loop();

    bool containsCall();
    uint32_t getAllBlocks(BasicBlock** arr);
    uint32_t getAllInstructions(X86Instruction** instructions, uint32_t nexti);
    uint32_t getDepth() { return depth; }
    FlowGraph* getFlowGraph() { return flowGraph; }
    BasicBlock* getHead() { return head; }
    uint32_t getIndex() { return index; }
    uint32_t getNumberOfBlocks() { return blocks->size(); }
    uint32_t getNumberOfInstructions();
    BasicBlock* getTail() { return tail; }
    bool hasSharedHeader(Loop* loop);
    bool isBlockIn(uint32_t idx) { return blocks->contains(idx); }
    bool isIdenticalLoop(Loop* loop);
    bool isInnerLoopOf(Loop* loop);
    void mergeLoopInto(Loop* loopToBeMerged); // Merge a loop into this loop
    void print();
    void printLiveness();
    void setDepth(uint32_t d) { depth = d; }
    void setIndex(uint32_t idx) { index = idx; }
};

#endif // _Loop_h_

