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

#ifndef _SpatialLocalityPerMemOp_hpp_
#define _SpatialLocalityPerMemOp_hpp_

#include <ReuseDistanceASI.hpp>
#include <ReuseDistance.hpp>  // external SpatialLocality

#include <string>

typedef struct AddressStreamStats_s AddressStreamStats;

class SpatialLocalityPerMemOpTool : public AddressStreamTool {
  public:
    SpatialLocalityPerMemOpTool() : AddressStreamTool() {}
    virtual void AddNewHandlers(AddressStreamStats* stats);
    virtual void AddNewStreamStats(AddressStreamStats* stats);
    virtual uint32_t CreateHandlers(uint32_t index, StringParser* parser);
    virtual void FinalizeTool(DataManager<AddressStreamStats*>* AllData, 
      SamplingMethod* Sampler);
    void SpatialLocalityPerMemOpFileName(AddressStreamStats* stats, std::string& oFile);
};


// Really just does what the ReuseStreamStats does 
//TODO Might want to edit this a bit
/*class SpatialStreamStats : public ReuseStreamStats {
  public:
    SpatialStreamStats(AddressStreamStats* stats) : ReuseStreamStats(stats) {};
};*/

// Very similar to Reuse Distance Handler but built a little differently
//TODO also very similar to the SpatialLocalityPerMemOpHandler
class SpatialLocalityPerMemOpHandler : public ReuseDistanceHandler {
  public:
    uint64_t window;
    uint64_t bin;
    uint64_t nmax;

    SpatialLocalityPerMemOpHandler(uint64_t w, uint64_t b, uint64_t n);
    SpatialLocalityPerMemOpHandler(SpatialLocalityPerMemOpHandler &h);
    ~SpatialLocalityPerMemOpHandler();
    //<memOp, external/SpatialLocality>
    pebil_map_type<uint64_t, ReuseDistance*>* mapInternalHandler; 
    //<blockId, memOp>
    //pebil_map_type<uint64_t, std::set<uint64_t>*>* blockMemopMapper;
    //<memOp, blockId>
    pebil_map_type<uint64_t, uint64_t>* memopBlockMapper;

    //TODO
    uint32_t Process(void* stats, BufferEntry* access);
    void SpatialLocalityPerMemOpHandler::SkipAddresses(uint32_t numToSkip);

    void PrintHeader(std::ostream& f);
    void PrintBlockInfo(std::ostream& f, uint64_t block, std::vector<uint64_t>* vec);
    void PrintMemOpInfo(std::ostream& f, uint64_t memop, ReuseDistance* rd, reuse_map_type<uint64_t,uint64_t> BinTotal);

};

#endif /* _SpatialLocalityPerMemOp_hpp_ */
