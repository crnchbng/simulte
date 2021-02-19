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

#ifndef __ARTERY_LTERRCUE_H_
#define __ARTERY_LTERRCUE_H_

#include <omnetpp.h>
#include "LteRrcBase.h"
#include "stack/phy/layer/LtePhyBase.h"
#include "stack/phy/layer/LtePhyUe.h"
#include "common/LteControlInfo_m.h"
#include"control/packet/RRCConnSetUp.h"
#include "control/packet/MIBSL.h"
#include "control/packet/SIB21.h"
#include "stack/pdcp_rrc/layer/LtePdcpRrc.h"

using namespace omnetpp;

/**
 * TODO - Generated class
 */
#define FSM_DEBUG

class SIB21Request;

class LteRrcUe :  public LteRrcBase
{
public:
    UserControlInfo* lteInfo;
    double ueDistanceFromEnb ;
    bool cellFound;
    bool dataArrivalStatus;
    /** Statistic for serving cell */
    simsignal_t servingCell_;
protected:

    LteSidelinkMode mode;
    LteRrcState state;
    cFSM fsm;
    simtime_t connRequestSent;
    simtime_t connRequestReceived;
    simtime_t sibReceived;
    //double detectionLatency;

    enum states {
        IDLE = 0,CONN = FSM_Steady(1),INACTIVE = FSM_Steady(2)
    };

    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);
    virtual void handleSelfMessage();
    bool checkCellCoverage();
    LteSidelinkMode modeSelect(bool);
    void connectionRequest(bool);
    void requestSIB21FromEnb();
    void requestMIBSLFromEnb();
    void SIB21PreConfigured();
    bool checkForDataTransmission();
};

#endif
