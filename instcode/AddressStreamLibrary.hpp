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

#ifndef _AddressStreamLibrary_hpp_
#define _AddressStreamLibrary_hpp_

#include <string>
#include <AddressStreamStats.hpp>

extern "C" {
    void* tool_mpi_init();
    void* tool_thread_init(pthread_t tid);
    void* process_buffer(image_key_t* key);
    void* tool_image_fini(image_key_t* key);
};

void GetBufferIds(BufferEntry* b, image_key_t* i);
void ReadSettings();
AddressStreamStats* GenerateStreamStats(AddressStreamStats* stats, 
  uint32_t typ, image_key_t iid, thread_key_t tid, image_key_t firstimage);
uint64_t ReferenceStreamStats(AddressStreamStats* stats);
void DeleteStreamStats(AddressStreamStats* stats);
void PrintAddressStreamStats(std::ofstream& f, AddressStreamStats* stats, 
  thread_key_t tid, bool perThread);


#endif /* _AddressStreamLibrary_cpp_ */

