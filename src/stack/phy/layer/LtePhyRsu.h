//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#ifndef _LTE_LTEMACRELAYUE_H_
#define _LTE_LTEMACRELAYUE_H_

#include "stack/phy/layer/LtePhyBase.h"

class LtePhyRsu : public LtePhyBase
{
protected:

    /** Self message to trigger broadcast message sending for handover purposes */
    cMessage *bdcStarter_;

    /** Broadcast messages interval (equal to updatePos interval for mobility) */
    double bdcUpdateInterval_;

    /** Master MacNodeId */
    MacNodeId masterId_;
    virtual void initialize(int stage);
    void handleAirFrame(cMessage* msg);
    void handleSelfMessage(cMessage *msg);
public:
    LtePhyRsu();
    virtual ~LtePhyRsu();
};

#endif
