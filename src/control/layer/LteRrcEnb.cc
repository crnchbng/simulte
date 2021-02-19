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

#include "LteRrcEnb.h"

using namespace omnetpp;

Define_Module(LteRrcEnb);

void LteRrcEnb::setPhy( LtePhyBase * phy ) { phy_ = phy ; }

void LteRrcEnb::initialize(int stage)
{

    // TODO - Generated method body
    nodeType_ = ENODEB;
    LteRrcBase::initialize(stage);
    WATCH(nodeType_);
    rrcRequestCounter=0;

}

void LteRrcEnb::handleMessage(cMessage *msg)
{
    EV <<"LteRrcEnb::handleSelfMessage Scanning for cellular coverage"<< endl;

    if (msg->isSelfMessage())
    {

        handleSelfMessage();
        nextMIBTransmission = simTime() + (160*TTI); //MIB-SL for SL-V2X
        EV<<"Next expected MIB transmission: "<<  nextMIBTransmission <<endl;
        frame= scheduleSystemInformation();
        scheduleAt(simTime()+(160*TTI), ttiTick_);
        return;
    }
    cPacket* pkt = check_and_cast<cPacket*>(msg);


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

    }

}

void LteRrcEnb::handleSelfMessage()
{
    EV <<"LteRrcEnb::handleSelfMessage"<< endl;
    scheduleSystemInformation();

}

LteAirFrame* LteRrcEnb::scheduleSystemInformation()
{
    EV<<"eNodeB generates MIB periodically"<<endl;
    //Setting MIB-SL parameters
    MIBSL* mib = new MIBSL("MIBSL");
    mib->setSlBandwidth(50);
    mib->setCellFound(true);
    mib->setDirectFrameNumber(1);
    mib->setDirectSubFrameNumber(1);
    mib->setTimestamp(simTime());

    //Schedule the packet with periodicity of 40 ms
    // create LteAirFrame and encapsulate a feedback packet
    LteAirFrame* frame = new LteAirFrame("MIBSL");
    frame->encapsulate(check_and_cast<cPacket*>(mib));
    frame->setDuration(TTI);
    return frame;

}

void LteRrcEnb::handleConnRequest(cPacket* pkt)
{
    EV<<"eNodeB handles RRC_conn_set_up_request"<<endl;
    LteAirFrame* frame = check_and_cast<LteAirFrame*>(pkt);
    UserControlInfo* uinfo =  check_and_cast<UserControlInfo*>(frame->getControlInfo());
    cPacket* connpkt=frame->decapsulate();
    RRCConnSetUp* connSetUp = check_and_cast<RRCConnSetUp*> (connpkt);
    //Prepare conn set-up
    connSetUp->setConnSetUp(true);
    propagationDelay = 0.004; //Processing delay

    EV<<"No of requests: "<<rrcRequestCounter<<endl;
    EV<<"No of users: "<<NumberOfExistingUsers<<endl;
    OmnetId destOmnetId = binder_->getOmnetId(uinfo->getSourceId());  //Here UE is the destination
    connSetUp->setConnSetUp(true);
    uinfo->setDestId(destOmnetId);
    uinfo->setSourceId(masterId_);
    uinfo->setFrameType(RRCSETUPREQUESTPKT);
    uinfo->setIsCorruptible(false);
    frame->setDuration(TTI);

    if (destOmnetId!=0)
    {
        sendRrcMessage(frame,destOmnetId, propagationDelay);
    }
    else
    {
        EV<<"Destination OmnetId: "<<destOmnetId<<endl;

        delete pkt;
    }


}


void LteRrcEnb::handleMIBRequest(cPacket* pkt)
{
    LteAirFrame* frame = check_and_cast<LteAirFrame*>(pkt);
    UserControlInfo* uinfo =  check_and_cast<UserControlInfo*>(frame->getControlInfo());
    cPacket* mibslpkt=frame->decapsulate();
    MIBSL* mibsl = check_and_cast< MIBSL*> (mibslpkt);
    //Prepare conn set-up

    mibsl->setSlBandwidth(50);
    mibsl->setCellFound(true);
    mibsl->setDirectFrameNumber(1);
    mibsl->setDirectSubFrameNumber(1);
    mibsl->setTimestamp(simTime());
    mibsl->setnextMIBTransmission(nextMIBTransmission.dbl());
    simtime_t delay = nextMIBTransmission+TTI;
    simtime_t currenttime = NOW;

    if (currenttime>delay)
    {
        propagationDelay=currenttime-delay;
    }
    else
    {
        propagationDelay=delay-currenttime;
    }


    EV<<"LteRrcEnb::handleMIBRequest: "<<nextMIBTransmission<<endl;
    OmnetId destOmnetId = binder_->getOmnetId(uinfo->getSourceId());  //Here UE is the destination

    uinfo->setDestId(destOmnetId);
    uinfo->setSourceId(masterId_);
    uinfo->setFrameType(MIBSLREQUESTPKT);
    uinfo->setIsCorruptible(false);
    frame->setDuration(TTI);
    if (destOmnetId!=0)
    {
        sendRrcMessage(frame,destOmnetId,propagationDelay);
    }
    else
    {
        EV<<"Destination OmnetId: "<<destOmnetId<<endl;
        delete pkt;
        //throw cRuntimeError("No UE in simulation");
    }

    EV<<"eNB configures MIB-SL for UE"<<endl;

}

void LteRrcEnb::handleSIB21Request(cPacket* pkt)
{
    EV<<"eNodeB handles SIB-21 request"<<endl;
    LteAirFrame* frame = check_and_cast<LteAirFrame*>(pkt);
    UserControlInfo* uinfo =  check_and_cast<UserControlInfo*>(frame->getControlInfo());
    cPacket* sib21pkt=frame->decapsulate();
    SIB21* sib = check_and_cast< SIB21*> (sib21pkt);

    sib->setAdjacencyPscchpssch(true);
    sib->setNumSubchannel(5);
    sib->setSizeSubchannel(5);
    sib->setStartRbSubchannel(0);
    propagationDelay = 0;
    OmnetId destOmnetId = binder_->getOmnetId(uinfo->getSourceId());  //Here UE is the destination

    uinfo->setDestId(destOmnetId);
    uinfo->setSourceId(masterId_);
    uinfo->setFrameType(SIB21REQUESTPKT);
    uinfo->setIsCorruptible(false);
    frame->setDuration(TTI);
    if (destOmnetId!=0)
    {
        sendRrcMessage(frame,destOmnetId,propagationDelay);
    }
    else
    {
        EV<<"Destination OmnetId: "<<destOmnetId<<endl;
        delete pkt;
        //throw cRuntimeError("No UE in simulation");
    }

}





