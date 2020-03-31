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

void ReuseDistanceTool::AddNewHandlers(AddressStreamStats* stats) {
    ReuseDistanceHandler* oldHandler = (ReuseDistanceHandler*)(handlers[0]);
    ReuseDistanceHandler* newHandler = new ReuseDistanceHandler(
      *oldHandler);
    stats->Handlers[indexInStats] = newHandler;
}

void ReuseDistanceTool::AddNewStreamStats(AddressStreamStats* stats) {
    stats->Stats[indexInStats] = new ReuseStreamStats(stats);
}

uint32_t ReuseDistanceTool::CreateHandlers(uint32_t index, StringParser* parser) {
    indexInStats = index;

    uint32_t reuseWindow;
    uint32_t reuseBin;
    if (!(parser->ReadEnvUint32("METASIM_REUSE_WINDOW", &reuseWindow))) {
        reuseWindow = 1;
    }
    if (!(parser->ReadEnvUint32("METASIM_REUSE_BIN", &reuseBin))) {
        reuseBin = 1;
    }

    handlers.push_back(new ReuseDistanceHandler(reuseWindow, reuseBin));
  
    return handlers.size();
}

void ReuseDistanceTool::FinalizeTool(DataManager<AddressStreamStats*>* AllData,
  SamplingMethod* Sampler) {
    // Create the Reuse Report(s)
    string oFile;
    const char* fileName;
    AddressStreamStats* stats = AllData->GetData(pthread_self());

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
    
            ReuseDistanceHandler* rd = (ReuseDistanceHandler*)(s->Handlers[
              indexInStats]);
            assert(rd);
            inform << "Reuse distance bins for " << hex << s->Application << " Thread " << AllData->GetThreadSequence(thread) << ENDL;
            rd->Print(ReuseDistFile);
        }
    }
    ReuseDistFile.close();
}

void ReuseDistanceTool::ReuseDistanceFileName(AddressStreamStats* stats, 
  string& oFile){
    oFile.clear();
    oFile.append(stats->Application);
    oFile.append(".r");
    AppendRankString(oFile);
    oFile.append(".t");
    AppendTasksString(oFile);
    oFile.append(".reusedist");
}

ReuseStreamStats::ReuseStreamStats(AddressStreamStats* stats) {
    numBlocks = stats->BlockCount;
    numMemops = stats->MemopCount;
    blockIds = (uint64_t*)malloc(sizeof(uint64_t) * numMemops);
    hashes = (uint64_t*)malloc(sizeof(uint64_t) * numBlocks);
    for (int32_t i = 0; i < numMemops; i++) {
        blockIds[i] = stats->BlockIds[i];
    }
    for (int32_t i = 0; i < numBlocks; i++) {
        hashes[i] = stats->Hashes[i];
    }
}

ReuseStreamStats::~ReuseStreamStats() {
    free(blockIds);
    free(hashes);
}

uint64_t ReuseStreamStats::GetBlock(uint32_t memop) {
    return blockIds[memop];
}

uint64_t ReuseStreamStats::GetHash(uint32_t memop) {
    return hashes[GetBlock(memop)];
}

ReuseDistanceHandler::ReuseDistanceHandler(uint64_t w, uint64_t b) {
    internalHandler = new ReuseDistance(w, b);
}

ReuseDistanceHandler::ReuseDistanceHandler(ReuseDistanceHandler& h) {
    internalHandler = new ReuseDistance(h.internalHandler);
}

ReuseDistanceHandler::~ReuseDistanceHandler() {
    delete internalHandler;
}

void ReuseDistanceHandler::Print(ofstream& f) {
    internalHandler->Print();
    internalHandler->Print(f, true);
}

uint32_t ReuseDistanceHandler::Process(void* stats, BufferEntry* access, uint64_t* Mapping) {
    ReuseStreamStats* s = (ReuseStreamStats*)stats;
    ReuseEntry entry = ReuseEntry();
    entry.id = s->GetHash(access->memseq);
    entry.address = access->address;
    internalHandler->Process(entry);
    return 0;
}

void ReuseDistanceHandler::SkipAddresses(uint32_t numToSkip) {
    internalHandler->SkipAddresses(numToSkip);
}
