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

#include <InstrumentationCommon.hpp>
#include <DataManager.hpp>
#include <DynamicInstrumentation.hpp>
#include <Metasim.hpp>
#include <ThreadedCommon.hpp>
#include <ReuseDistance.hpp>  // external ReuseDistance
#include <ReuseDistanceASI.hpp>
#include <AddressStreamStats.hpp>

#include <cstring>

using namespace std;

// These control reuse distance calculations. Activate this feature by setting 
// METASIM_REUSE_WINDOW to something other than 0. The design of the reuse 
// distance tool is such that tracking a large window size isn't a lot more 
// expensive than a small size. Also this will be rendered relatively useless
// unless the sampling period (METASIM_SAMPLE_ON) is somewhat large relative 
// to METASIM_REUSE_WINDOW.
//static const uint64_t ReuseCleanupMin = 10000000;
//static const double ReusePrintScale = 1.5;
//static const uint32_t ReuseIndivPrint = 32;

void PrintReuseDistanceFile(DataManager<AddressStreamStats*>* AllData, 
  int32_t reuseIndex) {
    // Create the Reuse Report(s)
    string oFile;
    const char* fileName;
    AddressStreamStats* stats = AllData->GetData(*(AllData->allimages.begin()));

    ofstream ReuseDistFile;
    ReuseDistanceFileName(stats, oFile);
    fileName = oFile.c_str();
    inform << "Printing reuse distance results to " << fileName << ENDL;
    TryOpen(ReuseDistFile, fileName);

    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); iit != AllData->allimages.end(); iit++){
        for(DataManager<AddressStreamStats*>::iterator it = AllData->begin(*iit); it != AllData->end(*iit); ++it) {

            thread_key_t thread = it->first;
            AddressStreamStats* s = it->second;
            ReuseDistFile << "IMAGE" << TAB << hex << (*iit) << TAB << "THREAD" << TAB << dec << AllData->GetThreadSequence(thread) << ENDL;
    
            ReuseDistance* rd = s->RHandlers[reuseIndex];
            assert(rd);
            inform << "Reuse distance bins for " << hex << s->Application << " Thread " << AllData->GetThreadSequence(thread) << ENDL;
            rd->Print();
            rd->Print(ReuseDistFile, true);
        }
    }
    ReuseDistFile.close();
}

void ReuseDistanceFileName(AddressStreamStats* stats, string& oFile){
    oFile.clear();
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".reusedist");
}
