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

extern "C" {
    void* tool_dynamic_init(uint64_t* count, DynamicInst** dyn, bool*
      isThreadedModeFlag);
    void* tool_mpi_init();
    void* tool_thread_init(thread_key_t tid);
    void* tool_thread_fini(thread_key_t tid);
    void* tool_image_init(void* s, image_key_t* key, ThreadData* td);
    void* tool_image_fini(image_key_t* key);
};

uint64_t ReferenceStreamStats(AddressStreamStats* stats);
void DeleteStreamStats(AddressStreamStats* stats);
AddressStreamStats* GenerateStreamStats(AddressStreamStats* stats, 
  uint32_t typ, image_key_t iid, thread_key_t tid, image_key_t firstimage);


#endif /* _AddressStreamLibrary_cpp_ */

