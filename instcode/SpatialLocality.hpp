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

#ifndef _SpatialLocality_hpp_
#define _SpatialLocality_hpp_

#include <ReuseDistanceASI.hpp>

#include <string>

typedef struct AddressStreamStats_s AddressStreamStats;

class SpatialLocalityTool : public AddressStreamTool {
  public:
    SpatialLocalityTool() : AddressStreamTool() {}
    virtual void AddNewHandlers(AddressStreamStats* stats);
    virtual void AddNewStreamStats(AddressStreamStats* stats);
    virtual uint32_t CreateHandlers(uint32_t index);
    virtual void FinalizeTool(DataManager<AddressStreamStats*>* AllData, 
      SamplingMethod* Sampler);
    void SpatialLocalityFileName(AddressStreamStats* stats, std::string& oFile);
};


// Really just does what the ReuseStreamStats does
class SpatialStreamStats : public ReuseStreamStats {
  public:
    SpatialStreamStats(AddressStreamStats* stats) : ReuseStreamStats(stats) {};
};

// Very similar to Reuse Distance Handler but built a little differently
class SpatialLocalityHandler : public ReuseDistanceHandler {
  public:
    SpatialLocalityHandler(uint64_t w, uint64_t b, uint64_t n);
    SpatialLocalityHandler(SpatialLocalityHandler &h);

};

#endif /* _SpatialLocality_hpp_ */
