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

#ifndef __ARTERY_LTERRCENB_H_
#define __ARTERY_LTERRCENB_H_

#include <omnetpp.h>
#include "LteRrcBase.h"
#include "common/LteCommon.h"
#include "control/packet/SIB21.h"
#include "control/packet/MIBSL.h"
#include "control/packet/RRCConnSetUp.h"
#include "common/LteControlInfo.h"
using namespace omnetpp;

/**
 * TODO - Generated class
 */
class LteRrcEnb :  public LteRrcBase
{
protected:

    LteAirFrame* frame;
    bool acceptsetUpRequest;
    int rrcRequestCounter;

    simtime_t nextMIBTransmission;
    simtime_t nextSIB21Transmission ;
    simtime_t waitingTimeMIB;
    simtime_t waitingTimeSIB21;

    //functions
    virtual void setPhy( LtePhyBase * phy );
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);
    virtual void handleSelfMessage();
    LteAirFrame* scheduleSystemInformation();
    void handleConnRequest(cPacket* );
    void handleMIBRequest(cPacket* );
    void handleSIB21Request(cPacket*);


};

#endif
