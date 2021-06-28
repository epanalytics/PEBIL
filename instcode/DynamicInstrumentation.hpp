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

#ifndef _DynamicInstrumentation_hpp_
#define _DynamicInstrumentation_hpp_

#include <cstdint>
#include <vector>
#include <set>

#ifdef HAVE_UNORDERED_MAP
#include <tr1/unordered_map>
#define pebil_map_type std::tr1::unordered_map
#else
#include <map>
#define pebil_map_type std::map
#endif

typedef struct DynamicInst_s DynamicInst;

class DynamicInstrumentation {
  protected:
    pebil_map_type < uint64_t, std::vector < DynamicInst* > > * Dynamics;
    bool ThreadedMode;
    
  public:
    DynamicInstrumentation();
    virtual ~DynamicInstrumentation();

    virtual void GetAllDynamicKeys(std::set<uint64_t>& keys);
    void InitializeDynamicInstrumentation(uint64_t* count, DynamicInst** dyn,
      bool* isThreadedModeFlag);
    virtual bool IsThreadedMode() { return ThreadedMode; }

    void PrintAllDynamicPoints(); 
    void PrintDynamicPoint(DynamicInst* d); 
    void SetDynamicPointStatus(DynamicInst* d, bool state);
    virtual void SetDynamicPoint(uint64_t key, bool state);
    virtual void SetDynamicPoints(std::set<uint64_t>& keys, bool state); 
    
};

#endif // _DynamicInstrumentation_hpp_
