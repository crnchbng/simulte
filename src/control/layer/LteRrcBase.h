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

#ifndef __CELLULARV2X_LTERRCBASE_H_
#define __CELLULARV2X_LTERRCBASE_H_

#include <omnetpp.h>
#include "common/LteCommon.h"
#include "world/radio/ChannelAccess.h"
#include "world/radio/ChannelControl.h"
#include "stack/phy/ChannelModel/LteChannelModel.h"
#include "stack/phy/feedback/LteFeedbackComputationRealistic.h"
#include "stack/phy/layer/LtePhyBase.h"
#include "common/LteControlInfo_m.h"
#include "corenetwork/binder/LteBinder.h"
#include "stack/phy/packet/LteAirFrame.h"
#include "common/LteControlInfo.h"
#include "stack/phy/layer/LtePhyBase.h"



using namespace omnetpp;


class LteChannelModel;
class LtePhyBase;
class LtepdcpRrcBase;
/**
 * TODO - Generated class
 */
#define UE_CATEGORY_DEFAULT "4"
#define UE_CATEGORY_MIN 1
#define UE_CATEGORY_MAX 21
#define RELEASE_DEFAULT 8
#define RELEASE_MIN 8
#define RELEASE_MAX 15
#define RRC_N_BANDS 43



class LteRrcBase: public cSimpleModule
{
public:
    LteNodeType nodeType_;
    MacNodeId masterId_;
    MacNodeId nodeId_;
    MacNodeId candidateMasterId_; //cadidate eNB with best RSSI
    //PHY interface
    bool sync;

    typedef struct {
        std::string ueCategoryStr;
        uint32_t    ueCategory;
        int         ueCategoryUl;
        int         ueCategoryDl;
        int         ueCategorySl;
        uint32_t    release;
        uint32_t    featureGroup;
        uint8_t     supportedBands[43]; //Standards
        uint32_t    numberOfSupportedBands;
        bool        supportCa;
        int         mbmsServiceId;
        uint32_t    mbmsServicePort;
    } rrcArgs;

    //getters and setters for SIB type ASN

    void getSignalStrengthMetrics(float rsrp, float rsrq, uint32_t tti, int earfcn, int pci);


protected:
    LteBinder* binder_;
    LtePhyBase* phy_;
    //Coordinates of UE and eNodeB
    inet::Coord ueCoord;
    inet::Coord enbCoord;
    bool forcedMode3Switch;
    bool forcedMode4Switch;
    int NumberOfExistingUsers;
    /// TTI self message
    cMessage* ttiTick_;
    cGate* PHY_IN;
    cGate* MAC_IN;
    cGate* PHY_OUT;
    cGate* MAC_OUT;
    cGate* control_IN;
    cGate* PDCP_control_IN;
    cGate* PDCP_control_OUT;
    simtime_t propagationDelay;
    simsignal_t detectionLatency;
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);
    /**
     * Main loop of the Mac level, calls the scheduler
     * and every other function every TTI : must be reimplemented
     * by derivate classes
     */
    virtual void handleSelfMessage() = 0;
    /**
     * Statistics recording
     */
    virtual void finish();
    /* cancel TT Timer*/
    virtual void deleteModule();
    void sendRrcMessage(LteAirFrame*, OmnetId destOmnetId, simtime_t propagationDelay);
    /**
     * Determine radio gate index of receiving node
     */
    int getReceiverGateIndex(const omnetpp::cModule*) const;
    inet::Coord getBaseStationCoord();
public:

};

#endif
