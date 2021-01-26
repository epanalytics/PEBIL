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

#ifndef _ReuseDistanceASI_hpp_
#define _ReuseDistanceASI_hpp_

#include <AddressStreamBase.hpp> 
#include <string>

#define INVALID_REUSE_DISTANCE (-1)

typedef struct AddressStreamStats_s AddressStreamStats;

class ReuseDistanceTool : public AddressStreamTool {
  public:
    ReuseDistanceTool() : AddressStreamTool() {}
    virtual void AddNewHandlers(AddressStreamStats* stats);
    virtual void AddNewStreamStats(AddressStreamStats* stats);
    virtual uint32_t CreateHandlers(uint32_t index, StringParser* parser);
    virtual void FinalizeTool(DataManager<AddressStreamStats*>* AllData,
      SamplingMethod* Sampler);
    void ReuseDistanceFileName(AddressStreamStats* stats, std::string& oFile);
};

class ReuseStreamStats : public StreamStats {
  private:
    uint32_t numBlocks; // copy of AddressStreamStats BlockCount
    uint32_t numMemops; // copy of AddressStreamStats MemopCount
    uint64_t* blockIds; // copy of AddressStreamStats BlockIds
    uint64_t* hashes;   // copy of AddressStreamStats Hashes
  public:
    ReuseStreamStats(AddressStreamStats* stats);
    virtual ~ReuseStreamStats();

    // FIXME
    uint64_t GetAccessCount(uint32_t memop) { return 0; }
    uint64_t GetBlock(uint32_t memop);
    virtual uint64_t GetHash(uint32_t memop);

    bool Verify() { return true; }
};

class ReuseDistanceHandler : public MemoryStreamHandler {
  protected:
    ReuseDistance* internalHandler;   // external ReuseDistance
  public:
    ReuseDistanceHandler(uint64_t w, uint64_t b);
    ReuseDistanceHandler(ReuseDistanceHandler &h);
    virtual ~ReuseDistanceHandler();

    void Print(std::ofstream& f);
    uint32_t Process(void* stats, BufferEntry* access);

    virtual void SkipAddresses(uint32_t numToSkip);
    bool Verify() { return true; }

    // Testing functions
    ReuseDistance* TestGetInternalHandler() { return internalHandler; }
    // END Testing functions
};

#endif /* _ReuseDistanceASI_hpp_ */
