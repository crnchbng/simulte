//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#ifndef _LTE_AIRPHYUED2D_H_
#define _LTE_AIRPHYUED2D_H_

#include "stack/phy/layer/LtePhyUe.h"
#include "stack/phy/resources/SidelinkResourceAllocation.h"
#include "stack/phy/packet/SidelinkControlInformation_m.h"
#include "common/LteCommon.h"
#include "stack/phy/layer/LtePhyEnbD2D.h"
#include "control/packet/RRCStateChange_m.h"


class LtePhyUeD2D : public LtePhyUe
{

protected:
    LteAirFrame* sciframe;
    LteAirFrame* frame;
    UserControlInfo* lteInfo;
    LtePhyEnbD2D* enb;
    LteSidelinkGrant* sciGrant_;
    cMessage* d2dDecodingTimer_;

    // D2D Tx Power
    double d2dTxPower_;
    bool halfDuplexError;
    bool receivedPacket;
    bool d2dMulticastEnableCaptureEffect_;
    double nearestDistance_;
    double bestRsrpMean_;
    bool frameSent;


    std::vector<std::tuple<double, int, int>> optimalCSRs;
    std::vector<LteAirFrame*> d2dReceivedFrames_;
    std::vector<double> rsrpVector;
    std::vector<double> bestRsrpVector_;

    simsignal_t subchannelsUsed;

    void storeAirFrame(LteAirFrame* newFrame);
    LteAirFrame* extractAirFrame();
    void decodeAirFrame(LteAirFrame* frame, UserControlInfo* lteInfo);
    virtual void initialize(int stage);
    virtual void finish();
    virtual void handleAirFrame(cMessage* msg);
    virtual void handleUpperMessage(cMessage* msg);
    virtual void handleSelfMessage(cMessage *msg);
    virtual void triggerHandover();
    virtual void doHandover();

public:
    LtePhyUeD2D();
    virtual ~LtePhyUeD2D();

    virtual void sendFeedback(LteFeedbackDoubleVector fbDl, LteFeedbackDoubleVector fbUl, FeedbackRequest req);
    virtual double getTxPwr(Direction dir = UNKNOWN_DIRECTION)
    {
        if (dir == D2D)
            return d2dTxPower_;
        return txPower_;
    }



};

#endif  /* _LTE_AIRPHYUED2D_H_ */
