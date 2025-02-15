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

#include "AlertNonIp.h"
#include "common/LteControlInfo.h"
#include "stack/phy/packet/cbr_m.h"
#include <omnetpp.h>


Define_Module(AlertNonIp);

void AlertNonIp::initialize(int stage)
{
    AlertNonIp::initialize(stage);
    if (stage==inet::INITSTAGE_LOCAL){
        // Register the node with the binder
        // Issue primarily is how do we set the link layer address

        // Get the binder
        binder_ = getBinder();

        // Get our UE
        cModule *ue = getParentModule();

        //Register with the binder
        nodeId_ = binder_->registerNode(ue, UE, 0);

        // Register the nodeId_ with the binder.
        binder_->setMacNodeId(nodeId_, nodeId_);
    } else if (stage==inet::INITSTAGE_APPLICATION_LAYER) {
        selfSender_ = NULL;
        nextSno_ = 0;

        selfSender_ = new cMessage("selfSender");

        size_ = par("packetSize");
        period_ = par("period");
        priority_ = par("priority");
        duration_ = par("duration");

        sentMsg_ = registerSignal("sentMsg");
        delay_ = registerSignal("delay");
        rcvdMsg_ = registerSignal("rcvdMsg");
        cbr_ = registerSignal("cbr");

        double delay = 0.001 * intuniform(0, 1000, 0);
        scheduleAt((simTime() + delay).trunc(SIMTIME_MS), selfSender_);
    }
}

void AlertNonIp::handleLowerMessage(cMessage* msg)
{
    if (msg->isName("CBR")) {
        Cbr* cbrPkt = check_and_cast<Cbr*>(msg);
        double channel_load = cbrPkt->getCbr();
        emit(cbr_, channel_load);
        delete cbrPkt;
    } else {
        AlertNonIpPacket* pkt = check_and_cast<AlertNonIpPacket*>(msg);

        if (pkt == 0)
            throw cRuntimeError("AlertNonIp::handleMessage - FATAL! Error when casting to AlertPacket");

        // emit statistics
        simtime_t delay = simTime() - pkt->getTimestamp();
        emit(delay_, delay);
        emit(rcvdMsg_, (long)1);

        EV << "AlertNonIp::handleMessage - Packet received: SeqNo[" << pkt->getSno() << "] Delay[" << delay << "]" << endl;

        delete msg;
    }
}

void AlertNonIp::handleSelfMessage(cMessage* msg)
{
    if (!strcmp(msg->getName(), "selfSender")){
        // Replace method

        //Packet* packet = new inet::Packet("AlertNonIpPacket");

        //auto alertnonip = inet::makeShared<AlertPacket>();


        AlertNonIpPacket* packet = new   AlertNonIpPacket("AlertNonIpPacket");
        packet->setTimestamp(simTime());
        packet->setBitLength(size_);
        packet->setSno(nextSno_);

        nextSno_++;

        auto lteControlInfo = new FlowControlInfoNonIp();

        lteControlInfo->setSrcAddr(nodeId_);
        lteControlInfo->setDirection(D2D_MULTI);
        lteControlInfo->setPriority(priority_);
        lteControlInfo->setDuration(duration_);
        lteControlInfo->setCreationTime(simTime());

        packet->setControlInfo(lteControlInfo);

        NonIpBase::sendLowerPackets(packet);
        emit(sentMsg_, (long)1);

        scheduleAt(simTime() + period_, selfSender_);
    }
    else
        throw cRuntimeError("AlertNonIp::handleMessage - Unrecognized self message");
}

void AlertNonIp::finish()
{
    cancelAndDelete(selfSender_);
}

AlertNonIp::~AlertNonIp()
{
    binder_->unregisterNode(nodeId_);
}
