//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//


//
// Packet used by the ~AlertSender and ~AlertReceiver modules.
//


import inet.common.packet.chunk.Chunk;
import inet.common.INETDefs;
packet AlertNonIpPacket 
{
    unsigned int sno;
    bool ipBased;
    int pktId;
    simtime_t timestamp;
}
