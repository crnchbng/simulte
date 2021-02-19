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

#include "LteRrcUe.h"
#include <omnetpp/cfsm.h>
#include <omnetpp.h>
#include "common/LteCommon.h"
#include "control/packet/RRCStateChange_m.h"



#define FSM_DEBUG

using namespace omnetpp;

Define_Module(LteRrcUe);


void LteRrcUe::initialize(int stage)
{
    nodeType_=UE;
    LteRrcBase::initialize(stage);
    dataArrivalStatus = false;
    EV<<"LteRrcUe::initialize"<<masterId_<<endl;
    if (stage == inet::INITSTAGE_LOCAL)
    {
        //Feedback from PHY layer about the candidate eNodeB
        servingCell_ = registerSignal("servingCell");

    }
    //initialize resource allocation mode
    if (stage == 3)
    {
        EV <<"LteRrcUe::initialize Configure resource allocation mode when UEs enter the simulation environment"<< endl;

        bool cellFound = checkCellCoverage();
        modeSelect(cellFound);
    }

}
void LteRrcUe::handleMessage(cMessage *msg)
{
    // TODO - Generated method body
    if (msg->isSelfMessage())
    {
        handleSelfMessage();
        return;
    }

    else if (msg->isName("RRC_conn_setup_request"))
    {
        connRequestReceived = NOW;
        EV<<"Received RRC_CONN_Request: "<<connRequestReceived<<endl;
        checkForDataTransmission();
    }
    else if (msg->isName("Data Arrival"))
    {
        dataArrivalStatus=true;
        return;
    }

    UserControlInfo* lteInfo = check_and_cast<UserControlInfo*>(msg->removeControlInfo());
    LteAirFrame* frame = check_and_cast<LteAirFrame*>(msg);
    cPacket* pkt = frame->decapsulate();
    if(lteInfo->getFrameType()==MIBSLREQUESTPKT)
    {
        EV<<"UE received MIB_SL_Request"<<endl;
        cPacket* pkt = check_and_cast<cPacket*>(msg);
        requestSIB21FromEnb();
        send(pkt,PHY_OUT);
        return;
    }
    if (lteInfo->getFrameType()==SIB21REQUESTPKT)
    {
        cPacket* pkt = check_and_cast<cPacket*>(msg);
        sibReceived = NOW;
        EV<<"Received SIB-21 at: "<<sibReceived;

        //detectionLatency = (sibReceived-connRequestSent).dbl();
        emit(detectionLatency, (sibReceived-connRequestSent).dbl());
        EV<<"Detection latency: "<< (sibReceived-connRequestSent).dbl()<<endl;
        send(pkt,PHY_OUT);
        return;
    }
    else
    {
        delete msg;
    }
}

void LteRrcUe::handleSelfMessage()
{
    EV <<"LteRrcUe::handleSelfMessage Track UE movement and check for cell coverage"<< endl;
    bool cellFound = checkCellCoverage();
    modeSelect(cellFound);
    scheduleAt(simTime()+TTI, ttiTick_);
}

bool  LteRrcUe::checkCellCoverage(){

    //Obtain positions of UE and eNB


    LtePhyBase* enb_ = check_and_cast<LtePhyBase*>(
            getSimulation()->getModule(binder_->getOmnetId(masterId_))->getSubmodule("lteNic")->getSubmodule("phy"));
    enbCoord = enb_->getCoord();
    EV<<"Coordinates of eNB: "<<enbCoord<<endl;

    LtePhyBase* ue_ = check_and_cast<LtePhyBase*>(
            getSimulation()->getModule(binder_->getOmnetId(nodeId_))->getSubmodule("lteNic")->getSubmodule("phy"));
    ueCoord = ue_->getCoord();

    ueDistanceFromEnb =ue_->getCoord().distance( enbCoord);



    if (ueDistanceFromEnb < 200)
    {
        //To set default mode 4, just put cellFound=false always
        cellFound=true;
        //Register to corresponding eNodeB
        binder_->registerNextHop(masterId_, nodeId_);
    }

    else{

        cellFound = false;
    }
    return cellFound;
}

LteSidelinkMode LteRrcUe::modeSelect(bool cellfound){

    //Initialize default mode
    RRCStateChange* rrcstate = new RRCStateChange("RRCStateChange");
    LteAirFrame* frame = new LteAirFrame("RRCStateChange");
    EV<<"Cell Found: "<<cellFound<<endl;


    /*    if (cellFound==true)
    {
        mode = MODE3;
        state = RRC_CONN;
        rrcstate->setState("RRC_CONN");

        EV<<"RRC mode: "<<LteSidelinkModeToA(mode)<<"state: "<<state<<endl;
        connectionRequest(cellFound);
        send(rrcstate,MAC_OUT);
    }
    else if (cellFound==false)
    {
        state= RRC_IDLE;
        rrcstate->setState("RRC_IDLE");

        mode = MODE4;
        EV<<"RRC mode: "<<mode<<"state: "<<state<<endl;

        //send pre-configured SL parameters

        SIB21PreConfigured();
        send(rrcstate,MAC_OUT);
    }
    else
    {
        throw cRuntimeError("Invalid cell conditions");
    }*/


    /// FSM implementation

    FSM_Switch(fsm)
    {
case FSM_Exit(IDLE):
                                                        {
    if(cellfound==true)
    {
        FSM_Goto(fsm,CONN);
        forcedMode3Switch=1;
    }

    break;
                                                        }
case FSM_Enter(CONN):
                                                    {
    rrcstate->setState("RRC_CONN");
    mode = MODE3;
    EV<<"Entered CONN state: "<<endl;
    EV<<"RRC mode: "<<LteSidelinkModeToA(mode)<<"state: "<<fsm.getStateName()<<endl;


    if (forcedMode3Switch)
    {
        connectionRequest(cellFound);
    }

    send(rrcstate,MAC_OUT);
    forcedMode3Switch=0;
    break;
                                                    }

case FSM_Exit(CONN):
                                                    {
    if(cellfound==false)
    {
        mode = MODE4;
        rrcstate->setState("RRC_IDLE");
        FSM_Goto(fsm, IDLE);
        forcedMode4Switch=1;
    }

    if (cellfound == true && dataArrivalStatus == false)
    {
        mode = MODE3;
        rrcstate->setState("RRC_INACTIVE");
        FSM_Goto(fsm, INACTIVE);
    }

    break;
                                                    }

case FSM_Enter(IDLE):
                                                    {
    mode = MODE4;
    rrcstate->setState("RRC_IDLE");
    EV<<"RRC mode: "<<LteSidelinkModeToA(mode)<<"state: "<<fsm.getStateName()<<endl;

    //send pre-configured SL parameters

    SIB21PreConfigured();
    send(rrcstate,MAC_OUT);


    break;
                                                    }

case FSM_Enter(INACTIVE):
                {
    mode = MODE3;
    rrcstate->setState("RRC_INACTIVE");
    EV<<"RRC mode: "<<LteSidelinkModeToA(mode)<<"state: "<<fsm.getStateName()<<endl;

    send(rrcstate,MAC_OUT);

    break;

                }

case FSM_Exit(INACTIVE):
                {
    if (cellfound == true && dataArrivalStatus == true)
    {
        mode = MODE3;
        rrcstate->setState("RRC_CONN");
        FSM_Goto(fsm, CONN);
        forcedMode3Switch=1;
    }
    if (cellfound == false)
    {
        mode = MODE4;
        rrcstate->setState("RRC_IDLE");
        FSM_Goto(fsm, IDLE);
    }

                }

    }

    //Notify PHY layer about mode
    return mode;
}

void LteRrcUe::connectionRequest(bool cellFound)
{
    //Request for connection set-up
    EV<<"UE sends RRC_conn_set_up_request"<<endl;
    RRCConnSetUp* connSetUp = new RRCConnSetUp("RRC_conn_setup_request");
    LteAirFrame* frame = new LteAirFrame("RRC_conn_setup_request");
    propagationDelay = TTI;
    //Setting MIB fields
    connSetUp->setCellfound("true");
    connSetUp->setConnSetUp("false");  //Default
    UserControlInfo* uinfo = new UserControlInfo();

    uinfo->setSourceId(nodeId_);
    uinfo->setDestId(candidateMasterId_);
    uinfo->setFrameType(RRCSETUPREQUESTPKT);
    uinfo->setIsCorruptible(false);

    frame->encapsulate(check_and_cast<cPacket*>(connSetUp));
    frame->setDuration(TTI);
    frame->setControlInfo(uinfo);

    OmnetId destOmnetId = binder_->getOmnetId(1);
    sendRrcMessage(frame,destOmnetId,propagationDelay);
    connRequestSent = NOW;

}

void LteRrcUe::requestMIBSLFromEnb()
{
    EV<<"Ue sends MIB-SL request to eNB"<<endl;
    MIBSL* mibsl = new MIBSL("MIB_SL_request");
    propagationDelay = TTI;
    LteAirFrame* frame = new LteAirFrame("MIB_SL_request");
    mibsl->setCellFound(cellFound);
    UserControlInfo* uinfo = new UserControlInfo();
    uinfo->setSourceId(nodeId_);
    uinfo->setDestId(candidateMasterId_);
    uinfo->setFrameType(MIBSLREQUESTPKT);
    uinfo->setIsCorruptible(false);

    frame->encapsulate(check_and_cast<cPacket*>(mibsl));
    frame->setDuration(TTI);
    frame->setControlInfo(uinfo);
    OmnetId destOmnetId = binder_->getOmnetId(1);
    sendRrcMessage(frame,destOmnetId,propagationDelay);
}


void LteRrcUe::requestSIB21FromEnb()
{
    EV<<"UE sends SIB-21 request"<<endl;
    SIB21* sibrequest = new SIB21("SIB21Request");
    LteAirFrame* frame = new LteAirFrame("SIB21Request");
    UserControlInfo* uinfo = new UserControlInfo();
    propagationDelay = TTI;
    uinfo->setSourceId(nodeId_);
    uinfo->setDestId(candidateMasterId_);
    uinfo->setFrameType(SIB21REQUESTPKT);
    uinfo->setIsCorruptible(false);
    frame->encapsulate(check_and_cast<cPacket*>(sibrequest));
    frame->setDuration(TTI);
    frame->setControlInfo(uinfo);
    OmnetId destOmnetId = binder_->getOmnetId(1);
    sendRrcMessage(frame,destOmnetId,propagationDelay);
}

bool LteRrcUe::checkForDataTransmission()
{

    if (dataArrivalStatus)
    {
        requestMIBSLFromEnb();
    }

    dataArrivalStatus=false;
    return dataArrivalStatus;
}


void LteRrcUe::SIB21PreConfigured()
{


    SIB21* sib21 = new SIB21("SIB21PreConfigured");

    //Pre-configured parameters of SIB-18
    sib21->setSlOffsetIndicator(0);
    sib21->setSizeSubchannel(5);
    sib21->setNumSubchannel(5);

    sib21->setStartRbSubchannel(0);
    send(sib21,PHY_OUT);

}

