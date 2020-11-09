//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#ifndef _LTE_RRCRSUENB_H_
#define _LTE_RRCRSUENB_H_

#include <omnetpp.h>
#include "LteRrcBase.h"
#include "common/LteCommon.h"
using namespace omnetpp;


class LteRrcRsuEnb : public LteRrcBase
{
protected:
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);
    virtual void handleSelfMessage();
    virtual void setPhy( LtePhyBase * phy );
public:

};

#endif  /* _LTE_AIRPHYENB_H_ */
