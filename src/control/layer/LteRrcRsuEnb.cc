//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#include "LteRrcRsuEnb.h"
#include "common/LteCommon.h"

Define_Module(LteRrcRsuEnb);


void LteRrcRsuEnb::setPhy( LtePhyBase * phy ) { phy_ = phy ; }

void LteRrcRsuEnb::initialize(int stage)
{

    // TODO - Generated method body
    nodeType_ = RSUEnB;
    LteRrcBase::initialize(stage);
    WATCH(nodeType_);

}

void LteRrcRsuEnb::handleMessage(cMessage *msg)
{
   EV <<"LteRrcRsuEnb::handleSelfMessage Scanning for cellular coverage"<< endl;

    if (msg->isSelfMessage())
    {

        //handleSelfMessage();
        /*nextMIBTransmission = simTime() + (160*TTI); //MIB-SL for SL-V2X
        EV<<"Next expected MIB transmission: "<<  nextMIBTransmission <<endl;
        frame= scheduleSystemInformation();
        scheduleAt(simTime()+(160*TTI), ttiTick_);
        return;*/
    }
    /*cPacket* pkt = check_and_cast<cPacket*>(msg);


    if(msg->isName("RRC_conn_setup_request"))
    {
        EV<<"eNodeB received RRC connection set up request from UE"<<endl;
        handleConnRequest(pkt);
        return;
    }

    if(msg->isName("MIB_SL_request"))
    {
        handleMIBRequest(pkt);
        return;
    }

    if(msg->isName("SIB21Request"))
    {
        handleSIB21Request(pkt);
        return;

    }*/

}


void LteRrcRsuEnb::handleSelfMessage()
{

}
