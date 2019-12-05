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

#ifndef _AddressRange_hpp_
#define _AddressRange_hpp_

#include <AddressStreamBase.hpp>
#include <string>

class AddressRangeTool : public AddressStreamTool {
  public:
    AddressRangeTool() : AddressStreamTool() {}
    virtual void AddNewHandlers(AddressStreamStats* stats);
    virtual void AddNewStreamStats(AddressStreamStats* stats);
    virtual uint32_t CreateHandlers(uint32_t index);
    virtual void FinalizeTool(DataManager<AddressStreamStats*>* AllData,
      SamplingMethod* Sampler);
    void RangeFileName(AddressStreamStats* stats, std::string& oFile);
};


struct AddressRange {
    uint64_t Minimum;
    uint64_t Maximum;
};

class RangeStats : public StreamStats {
private:
    static const uint64_t MAX_64BIT_VALUE = 0xffffffffffffffff;

    uint32_t Capacity;
    uint64_t* Counts;
    AddressRange** Ranges;

public:

    RangeStats(uint32_t capacity);
    virtual ~RangeStats();

    bool HasMemId(uint32_t memid);
    uint64_t GetAccessCount(uint32_t memid) { return Counts[memid]; }
    uint32_t GetCapacity() { return Capacity; }
    uint64_t GetMinimum(uint32_t memid);
    uint64_t GetMaximum(uint32_t memid);

    virtual void Update(uint32_t memid, uint64_t addr);
    virtual void Update(uint32_t memid, uint64_t addr, uint32_t count);

    bool Verify();
};

class AddressRangeHandler : public MemoryStreamHandler {
public:
    AddressRangeHandler();
    ~AddressRangeHandler();

    void Print(std::ofstream& f);
    uint32_t Process(void* stats, BufferEntry* access);
    bool Verify() { return true; }
};


#endif /* _AddressRange_hpp_ */

