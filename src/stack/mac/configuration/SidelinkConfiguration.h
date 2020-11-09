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

#ifndef __ARTERY_SIDELINKCONFIGURATION_H_
#define __ARTERY_SIDELINKCONFIGURATION_H_

#include <omnetpp.h>
#include "corenetwork/lteCellInfo/LteCellInfo.h"
#include "stack/mac/layer/LteMacUeD2D.h"
#include "stack/mac/amc/LteAmc.h"
#include "common/LteControlInfo.h"
#include <unordered_map>
#include <map>
#include <vector>
#include "boost/tuple/tuple.hpp"
#include <iostream>
#include <utility>      //
#include <algorithm>
#include "stack/mac/layer/LteMacBase.h"
#include "stack/mac/layer/LteMacUeD2D.h"
#include "stack/mac/layer/LteMacEnbD2D.h"
#include "stack/mac/packet/LteSidelinkGrant.h"
#include "corenetwork/binder/LteBinder.h"
#include "stack/mac/packet/DataArrival.h"
using namespace omnetpp;

/**
 * TODO - Generated class
 */



class SidelinkConfiguration : public cSimpleModule
{
    friend class LteMacUeD2D;
    friend class LteMacEnbD2D;
protected:
    cGate* up_[2];     /// RLC <--> MAC
    cGate* down_[2];   /// MAC <--> PHY
    /// Lte AMC module
    LteAmc *amc_;

    LteMacBase* mac;
    /// Local LteDeployer

    LteCellInfo* deployer_;
    LteBinder* binder_;
    LteSidelinkGrant* mode4Grant;
    LteSidelinkGrant* mode3Grant;
    LteSidelinkGrant* slGrant;
    LteSchedulerUeUl* lcgScheduler_;
    // configured grant - one each codeword
    LteSchedulingGrant* schedulingGrant_;

    /// List of scheduled connection for this UE
    LteMacScheduleList* scheduleList_;
    UserTxParams* preconfiguredTxParams_;
    UeInfo* ueInfo_;
    cGate* configure_IN;
    cGate* configure_OUT;

    int numAntennas_;
    MacNodeId nodeId_;
    MacNodeId masterId_;
    /// MacCellId
    MacCellId cellId_;
    MacNodeId  connectedNodeId_;
    LteNodeType nodeType_;
    // RAC Handling variables
    bool racD2DMulticastRequested_;
    // Multicast D2D BSR handling
    bool bsrD2DMulticastTriggered_;

    /// Mac Sdu Real Buffers
    LteMacBuffers mbuf_;
    /// Mac Sdu Virtual Buffers
    LteMacBufferMap macBuffers_;
    /// List of pdus finalized for each user on each codeword
    MacPduList macPduList_;
    /// Harq Tx Buffers
    HarqTxBuffers harqTxBuffers_;
    /// Harq Rx Buffers
    HarqRxBuffers harqRxBuffers_;
    std::string rrcCurrentState;
    bool firstTx;

    // All of the following should be configurable by the OMNet++ ini file and maybe even taken from higher layers if that's possible.
    double probResourceKeep_;
    int restrictResourceReservationPeriod;
    int minSubchannelNumberPSSCH_;
    int maxSubchannelNumberPSSCH_;
    double maximumLatency_;
    int subchannelSize_;
    int numSubchannels_;
    int minMCSPSSCH_;
    int maxMCSPSSCH_;
    int maximumCapacity_;
    int allowedRetxNumberPSSCH_;
    int reselectAfter_;
    int defaultCbrIndex_;
    int currentCbrIndex_;
    double channelOccupancyRatio_;
    double cbr_;
    bool useCBR_;
    bool packetDropping_;
    int missedTransmissions_;
    int resourceReselectionCounter_;
    int allocatedBlocksSCIandData;
    // perodic grant handling
    unsigned int periodCounter_;
    unsigned int expirationCounter_;
    double remainingTime_;
    int harqProcesses_;
    // current H-ARQ process counter
    unsigned char currentHarq_;
    Codeword currentCw_;
    McsTable dlMcsTable_;
    McsTable ulMcsTable_;
    McsTable d2dMcsTable_;
    double mcsScaleDl_;
    double mcsScaleUl_;
    double mcsScaleD2D_;
    bool expiredGrant_;
    // if true, use the preconfigured TX params for transmission, else use that signaled by the eNB
    bool usePreconfiguredTxParams_;

    std::map<UnitList, int> pduRecord_;
    std::vector<std::unordered_map<std::string, double>> cbrPSSCHTxConfigList_;
    std::vector<std::unordered_map<std::string, double>> cbrLevels_;
    std::unordered_map<double, int> previousTransmissions_;
    std::vector<double> validResourceReservationIntervals_;
    std::map<std::string, int> cbrLevelsMap;
    std::map<MacCid, FlowControlInfo> connDesc_;

    /* Incoming Connection Descriptors:
     * a connection is stored at the first MAC SDU delivered to the RLC
     */
    std::map<MacCid, FlowControlInfo> connDescIn_;

    simtime_t receivedTime_;
    simsignal_t grantStartTime;
    simsignal_t grantBreak;
    simsignal_t grantBreakTiming;
    simsignal_t grantBreakSize;
    simsignal_t droppedTimeout;
    simsignal_t grantBreakMissedTrans;
    simsignal_t missedTransmission;
    simsignal_t selectedMCS;
    simsignal_t selectedNumSubchannels;
    simsignal_t selectedSubchannelIndex;
    simsignal_t maximumCapacity;
    simsignal_t grantRequest;
    simsignal_t packetDropDCC;
    simsignal_t macNodeID;
    simsignal_t macBufferOverflowDl_;
    simsignal_t macBufferOverflowUl_;
    simsignal_t macBufferOverflowD2D_;
    simsignal_t receivedPacketFromUpperLayer;
    simsignal_t receivedPacketFromLowerLayer;
    simsignal_t sentPacketToUpperLayer;
    simsignal_t sentPacketToLowerLayer;
    simsignal_t measuredItbs_;
    simsignal_t dataSize;

    virtual int getNumAntennas();

    /**
     * Generate a scheduling grant
     */
    virtual LteSidelinkGrant* macGenerateSchedulingGrant(double maximumLatency, int priority, int tbSize);
    UserTxParams* getPreconfiguredTxParams();  // build and return new user tx params

    /**
     * Handles the SPS candidate resources message from the PHY layer.
     */

    /**
     * Reads MAC parameters for ue and performs initialization.
     */
    virtual void initialize(int stage);

    /**
     * Analyze gate of incoming packet
     * and call proper handler
     */
    virtual void handleMessage(cMessage *msg);

    /**
     * Main loop
     */
    virtual void handleSelfMessage();
    void assignGrantToData(DataArrival* , std::string );
    /**
     * macPduMake() creates MAC PDUs (one for each CID)
     * by extracting SDUs from Real Mac Buffers according
     * to the Schedule List.
     * It sends them to H-ARQ (at the moment lower layer)
     *
     * On UE it also adds a BSR control element to the MAC PDU
     * containing the size of its buffer (for that CID)
     */
    virtual void macPduMake();

    /**
     * Parse transmission configuration for a Ue
     */
    void parseUeTxConfig(cXMLElement* xmlConfig);

    /**
     * Parse transmission configuration for CBR
     */
    void parseCbrTxConfig(cXMLElement* xmlConfig);

    /**
     * Parse transmission configuration for Resource Reservation Intervals
     */
    void parseRriConfig(cXMLElement* xmlConfig);



    void finish();


public:
    virtual void macHandleSps(std::vector<std::tuple<double, int, double>> , std::string );

    SidelinkConfiguration();
    virtual ~SidelinkConfiguration();

    virtual bool isD2DCapable()
    {
        return true;
    }
    LteSidelinkGrant* getSidelinkGrant()
    {

        return slGrant;
    }
    virtual void setSidelinkGrant(LteSidelinkGrant*);
    /**
     * Purges PDUs from the HARQ buffers for sending to the PHY layer.
     */
    void flushHarqBuffers(HarqTxBuffers harqTxBuffers_, LteSidelinkGrant*);
    void setAllocatedBlocksSCIandData(int totalGrantedBlocks);
    int getAllocatedBlocksSCIandData()
    {
        return allocatedBlocksSCIandData;
    }

};


#endif
