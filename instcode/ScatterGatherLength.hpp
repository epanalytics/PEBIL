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

#ifndef _ScatterGatherLength_hpp_
#define _ScatterGatherLength_hpp_

#include <AddressStreamBase.hpp>
#include <string>

//class SamplingMethod;

class ScatterGatherLengthTool : public AddressStreamTool {
  private:
    int32_t indexInStats = -1;
  public:
    ScatterGatherLengthTool() : indexInStats(-1) {}
    virtual ~ScatterGatherLengthTool() {}
    virtual std::vector<MemoryStreamHandler*> CreateHandlers(uint32_t index);
    virtual void FinalizeTool(DataManager<AddressStreamStats*>* AllData, 
      SamplingMethod* Sampler);
    void SGLengthFileName(AddressStreamStats* stats, std::string& oFile);

    int32_t GetIndex() { return indexInStats; }
};

struct VectorLength {
    uint64_t Minimum;
    uint64_t Maximum;
    double Average;
};

class VectorLengthStats : public StreamStats {
private:
    static const uint64_t MAX_64BIT_VALUE = 0xffffffffffffffff;
public:
    uint32_t Capacity;
    VectorLength** Lengths;
    uint64_t* Counts;

    VectorLengthStats(uint32_t capacity);
    ~VectorLengthStats();

    bool HasMemId(uint32_t memid);
    double GetAverage(uint32_t memid);
    uint64_t GetMinimum(uint32_t memid);
    uint64_t GetMaximum(uint32_t memid);
    uint64_t GetAccessCount(uint32_t memid) { return Counts[memid]; }

    void Aggregate(uint32_t memid, uint64_t count, uint64_t min, uint64_t max, 
      double avg);
    void Update(uint32_t memid, uint64_t addr);

    bool Verify();
};

class VectorLengthHandler : public MemoryStreamHandler {
public:
    VectorLengthHandler();
    VectorLengthHandler(VectorLengthHandler& h);
    ~VectorLengthHandler();

    void Print(std::ofstream& f);
    uint32_t Process(void* stats, BufferEntry* access);
    bool Verify() { return true; }
};

#endif /* _ScattherGatherLength_hpp_ */

