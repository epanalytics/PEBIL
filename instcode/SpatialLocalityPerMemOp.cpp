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

void SpatialLocalityPerMemOpTool::AddNewHandlers(AddressStreamStats* stats) {
    SpatialLocalityPerMemOpHandler* oldHandler = (SpatialLocalityHandler*)(handlers[0]);
    SpatialLocalityPerMemOpHandler* newHandler = new SpatialLocalityPerMemOpHandler(
      *oldHandler);
    stats->Handlers[indexInStats] = newHandler;
}

void SpatialLocalityPerMemOpTool::AddNewStreamStats(AddressStreamStats* stats) {
    stats->Stats[indexInStats] = new SpatialStreamStats(stats);
}

uint32_t SpatialLocalityPerMemOpTool::CreateHandlers(uint32_t index, StringParser* parser) {
    indexInStats = index;

    uint32_t spatialWindow;
    uint32_t spatialBin;
    uint32_t spatialNMAX;
    if (!(parser->ReadEnvUint32("METASIM_SPATIAL_WINDOW", &spatialWindow))) {
        spatialWindow = 1;
    }
    if (!(parser->ReadEnvUint32("METASIM_SPATIAL_BIN", &spatialBin))) {
        spatialBin = 1;
    }
    if (!(parser->ReadEnvUint32("METASIM_SPATIAL_NMAX", &spatialNMAX))) {
        spatialNMAX = ReuseDistance::Infinity;
    }

    handlers.push_back(new SpatialLocalityPerMemOpHandler(spatialWindow, spatialBin,
      spatialNMAX));

    return handlers.size();
}

void SpatialLocalityPerMemOpTool::FinalizeTool(DataManager<AddressStreamStats*>* 
  AllData, SamplingMethod* sampler) {
    string oFile;
    const char* fileName;

    AddressStreamStats* stats = AllData->GetData(pthread_self());

    ofstream SpatialLocFile;
    SpatialLocalityPerMemOpFileName(stats, oFile);
    fileName = oFile.c_str();
    inform << "Printing spatial locality results to " << fileName << ENDL;
    TryOpen(SpatialLocFile, fileName);

    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); iit != AllData->allimages.end(); iit++){
        for(DataManager<AddressStreamStats*>::iterator it = AllData->begin(*iit); it != AllData->end(*iit); ++it){
            thread_key_t thread = it->first;
            AddressStreamStats* s = it->second;

            SpatialLocFile << "IMAGE" << TAB << hex << (*iit) << TAB << "THREAD" << TAB << dec << AllData->GetThreadSequence(thread) << ENDL;

            SpatialLocalityPerMemOpHandler* sd = (SpatialLocalityPerMemOpHandler*)(s->Handlers[
              indexInStats]);
            assert(sd);
            inform << "Spatial locality bins for " << hex << s->Application << " Thread " << AllData->GetThreadSequence(thread) << ENDL;
            sd->Print(SpatialLocFile);
        }
    }
    SpatialLocFile.close();

}

void SpatialLocalityPerMemOpTool::SpatialLocalityPerMemOpFileName(AddressStreamStats* stats, 
  string& oFile){
    oFile.clear();
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".spatial");
}

SpatialLocalityPerMemOpHandler::SpatialLocalityPerMemOpHandler(uint64_t w, uint64_t b, uint64_t
  n) : ReuseDistanceHandler(0, 0) {
    delete internalHandler;
    //internalHandler = new SpatialLocality(w, b, n);
    mapInternalHandler = new pebil_map_type<uint64_t, ReuseDistance*>();
    window = w;
    bin = b;
    nmax = n;
}

SpatialLocalityPerMemOpHandler::SpatialLocalityPerMemOpyHandler(SpatialLocalityPerMemOpHandler& h) :
  ReuseDistanceHandler(0, 0) {
    delete internalHandler;
    internalHandler = new SpatialLocality((SpatialLocality*)h.internalHandler);
}

SpatialLocalityPerMemOpHandler::Process(void* stats, BufferEntry* access){
    uint64_t memOp = access->memseq;
    //not in map, add it, process it
    if (mapInternalHandler->find(memOp) = mapInternalHandler->end()) {
        ReuseDistance* individualMemOpSpatialLocality = new ReuseDistance();
        std::pair<uint64_t, ReuseDistance*> kvp (memOp, individualMemOpSpatialLocality);
        mapInternalHandler->insert(kvp);
    } else { //in map, grap it, process it
        //TODOTODO
    }
}
