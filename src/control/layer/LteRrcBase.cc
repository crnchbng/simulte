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

#include "LteRrcBase.h"
#include <omnetpp.h>
#include "corenetwork/lteip/IP2lte.h"


void LteRrcBase::initialize(int stage)
{

    if (stage == inet::INITSTAGE_LOCAL)
    {
        EV<<"LteRrcBase::initialize"<<nodeType_<<endl;
        nodeTypeToA(nodeType_);
        detectionLatency = registerSignal("detectionLatency");

        binder_ = getBinder();
        if (nodeType_ == ENODEB)
        {
            // TODO not so elegant
            cModule *enodeb = getParentModule()->getParentModule();
            MacNodeId cellId = binder_->getEnbId();
            masterId_ = cellId;

            EV<<"LteRrcBase::initialize ENODEB "<< masterId_ ;
        }

        if (nodeType_ == UE)
        {
            // TODO not so elegant
            cModule *ue = getParentModule()->getParentModule();
            nodeId_ = binder_->getUeId();
            masterId_ = ue->par("masterId");
            EV<<"LteRrcBase::initialize UE "<<  nodeId_  ;
        }

        if (nodeType_==RSUEnB)
        {
            cModule *rsuEnb = getParentModule()->getParentModule();
            nodeId_ = binder_->getRsuEnbId();
            masterId_ = rsuEnb->par("masterId");
            EV<<"Initialize RSUEnb"<<nodeId_<<endl;
        }

        /* Gates initialization */
        PHY_IN = gate("PHY_control$i");
        MAC_IN = gate("MAC_control$i");
        PHY_OUT = gate("PHY_control$o");
        MAC_OUT=gate("MAC_control$o");
        control_IN=gate("control_IN");
        PDCP_control_IN=gate("PDCP_control$i");
        PDCP_control_OUT=gate("PDCP_control$o");
        EV<<"LteRrcBase::initialize starting TTimer"<<endl;
        ttiTick_ = new cMessage("ttiTick_");
        ttiTick_->setSchedulingPriority(1);        // TTI TICK after other messages
        scheduleAt(simTime()+TTI, ttiTick_);
        EV<<"LteRrcBase::initialize launched timer"<<endl;
    }
}

void LteRrcBase::handleMessage(cMessage *msg)
{
    EV<<"LteRrcBase::handleMessage"<< msg->getName()<<endl;
    if (msg->isSelfMessage())
    {
        handleSelfMessage();
        scheduleAt(NOW + TTI, ttiTick_);

        return;
    }
    cPacket* pkt = check_and_cast<cPacket *>(msg);
    EV << "LteRRCBase : Received packet " << pkt->getName() <<
            " from port " << pkt->getArrivalGate()->getName() << endl;


}


inet::Coord LteRrcBase::getBaseStationCoord()
{
    /*RadioDriver* rd = check_and_cast<RadioDriver*>(getSimulation()->getModuleByPath("radioDriverLte"));
    enbCoord=rd->getStationaryModulePosition();*/

}


void LteRrcBase::sendRrcMessage(LteAirFrame* pkt, OmnetId destOmnetId, simtime_t propagationDelay){

    // get a pointer to receiving module

    cModule *receiver = getSimulation()->getModule(destOmnetId);
    //
    EV<<"LteRrcBase::sendRrcMessage destination: "<<getReceiverGateIndex(receiver)<<endl;

    // receiver's gate
    sendDirect(pkt,  propagationDelay,TTI, receiver, getReceiverGateIndex(receiver));

}

int LteRrcBase::getReceiverGateIndex(const omnetpp::cModule *receiver) const
{

    //Check if the node is in the simulation


    int gate = receiver->findGate("control_IN");
    if (gate < 0)
    {
        gate = receiver->findGate("control_IN");
    }

    if (gate < 0) {
        throw cRuntimeError("receiver \"%s\" has no suitable radio input gate",
                receiver->getFullPath().c_str());
    }

    return gate;
}

void LteRrcBase::finish()
{
}

void LteRrcBase::deleteModule(){
    cancelAndDelete(ttiTick_);
    cSimpleModule::deleteModule();
}
