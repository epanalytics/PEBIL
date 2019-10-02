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
#include <ReuseDistance.hpp>  // external SpatialLocality
#include <SpatialLocality.hpp>
#include <AddressStreamStats.hpp>

#include <cstring>

using namespace std;

void PrintSpatialLocalityFile(DataManager<AddressStreamStats*>* AllData, int32_t
  spatialIndex) {
    string oFile;
    const char* fileName;

    AddressStreamStats* stats = AllData->GetData(*(AllData->allimages.begin()));

    ofstream SpatialLocFile;
    SpatialLocalityFileName(stats, oFile);
    fileName = oFile.c_str();
    inform << "Printing spatial locality results to " << fileName << ENDL;
    TryOpen(SpatialLocFile, fileName);

    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); iit != AllData->allimages.end(); iit++){
        for(DataManager<AddressStreamStats*>::iterator it = AllData->begin(*iit); it != AllData->end(*iit); ++it){
            thread_key_t thread = it->first;
            AddressStreamStats* s = it->second;

            SpatialLocFile << "IMAGE" << TAB << hex << (*iit) << TAB << "THREAD" << TAB << dec << AllData->GetThreadSequence(thread) << ENDL;

            ReuseDistance* sd = s->RHandlers[spatialIndex];
            assert(sd);
            inform << "Spatial locality bins for " << hex << s->Application << " Thread " << AllData->GetThreadSequence(thread) << ENDL;
            sd->Print();
            sd->Print(SpatialLocFile, true);
        }
    }
    SpatialLocFile.close();

}

void SpatialLocalityFileName(AddressStreamStats* stats, string& oFile){
    oFile.clear();
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".spatial");
}

