//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#include "NonIpConnectionsTable.h"

#include "stack/pdcp_rrc/NonIpConnectionsTable.h"

NonIpConnectionsTable::NonIpConnectionsTable()
{
    // Table is resetted by putting all fields equal to 0xFF
    memset(NonIpHt_, 0xFF, sizeof(struct entry_) * TABLE_SIZE);
}

unsigned int NonIpConnectionsTable::hash_func(long srcAddr, long dstAddr)
{
    return (srcAddr | dstAddr) % TABLE_SIZE;
}

unsigned int NonIpConnectionsTable::hash_func(long srcAddr, long dstAddr, uint16_t dir)
{
    return (srcAddr | dstAddr | dir) % TABLE_SIZE;
}

LogicalCid NonIpConnectionsTable::find_entry(long srcAddr, long dstAddr)
{
    int hashIndex = hash_func(srcAddr, dstAddr);
    while (1)
    {
        if (NonIpHt_[hashIndex].lcid_ == 0xFFFF)            // Entry not found
            return 0xFFFF;
        if (NonIpHt_[hashIndex].srcAddr_ == srcAddr &&
            NonIpHt_[hashIndex].dstAddr_ == dstAddr)
            return NonIpHt_[hashIndex].lcid_;                // Entry found
        hashIndex = (hashIndex + 1) % TABLE_SIZE;    // Linear scanning of the hash table
    }
}

LogicalCid NonIpConnectionsTable::find_entry(long srcAddr, long dstAddr, uint16_t dir)
{
    int hashIndex = hash_func(srcAddr, dstAddr, dir);
    while (1)
    {
        if (NonIpHt_[hashIndex].lcid_ == 0xFFFF)            // Entry not found
            return 0xFFFF;
        if (NonIpHt_[hashIndex].srcAddr_ == srcAddr &&
            NonIpHt_[hashIndex].dstAddr_ == dstAddr &&
            NonIpHt_[hashIndex].dir_ == dir)
            return NonIpHt_[hashIndex].lcid_;                // Entry found
        hashIndex = (hashIndex + 1) % TABLE_SIZE;    // Linear scanning of the hash table
    }
}

void NonIpConnectionsTable::create_entry(long srcAddr, long dstAddr, LogicalCid lcid)
{
    int hashIndex = hash_func(srcAddr, dstAddr);
    while (NonIpHt_[hashIndex].lcid_ != 0xFFFF)
        hashIndex = (hashIndex + 1) % TABLE_SIZE;    // Linear scanning of the hash table
    NonIpHt_[hashIndex].srcAddr_ = srcAddr;
    NonIpHt_[hashIndex].dstAddr_ = dstAddr;
    NonIpHt_[hashIndex].lcid_ = lcid;
    return;
}

void NonIpConnectionsTable::create_entry(long srcAddr, long dstAddr, uint16_t dir, LogicalCid lcid)
{
    int hashIndex = hash_func(srcAddr, dstAddr, dir);
    while (NonIpHt_[hashIndex].lcid_ != 0xFFFF)
        hashIndex = (hashIndex + 1) % TABLE_SIZE;    // Linear scanning of the hash table
    NonIpHt_[hashIndex].srcAddr_ = srcAddr;
    NonIpHt_[hashIndex].dstAddr_ = dstAddr;
    NonIpHt_[hashIndex].dir_ = dir;
    NonIpHt_[hashIndex].lcid_ = lcid;
    return;
}

NonIpConnectionsTable::~NonIpConnectionsTable()
{
    memset(NonIpHt_, 0xFF, sizeof(struct entry_) * TABLE_SIZE);
}
