//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#include "stack/pdcp_rrc/layer/LtePdcpRrcUeD2D.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "stack/d2dModeSelection/D2DModeSwitchNotification_m.h"
#include <vector>
#include "apps/alert/AlertPacket_m.h"
Define_Module(LtePdcpRrcUeD2D);
void LtePdcpRrcUeD2D::initialize(int stage)
{
    EV << "LtePdcpRrcUeD2D::initialize() - stage " << stage << endl;
    LtePdcpRrcUe::initialize(stage);
    if (stage == INITSTAGE_NETWORK_LAYER_3+1)
    {
        // inform the Binder about the D2D capabilities of this node
        // i.e. the (possibly) D2D peering UEs
        numberAlertPackets = 0;
        const char *d2dPeerAddresses = getAncestorPar("d2dPeerAddresses");
        cStringTokenizer tokenizer(d2dPeerAddresses);
        const char *token;
        while ((token = tokenizer.nextToken()) != NULL)
        {
            std::pair<const char*, bool> p(token,false);
            d2dPeeringInit_.insert(p);

            // delay initialization D2D capabilities to once arrive the first packet to the destination
        }

        retrievedPktId = 1000;
        retrievedCAMId = 5000;
    }
}

MacNodeId LtePdcpRrcUeD2D::getDestId(FlowControlInfo* lteInfo)
{
    IPv4Address destAddr = IPv4Address(lteInfo->getDstAddr());
    MacNodeId destId = binder_->getMacNodeId(destAddr);

    // check if the destination is inside the LTE network
    if (destId == 0 || getDirection(destId) == UL)  // if not, the packet is destined to the eNB
    {
        // UE is subject to handovers: master may change
        return binder_->getNextHop(nodeId_);
    }

    return destId;
}

/*
 * Upper Layer handlers
 */
void LtePdcpRrcUeD2D::fromDataPort(cPacket *pkt)
{
    EV<<"LtePdcpRrcUeD2D::fromDataPort: "<<pkt->getName()<<endl;

    emit(receivedPacketFromUpperLayer, pkt);
    LogicalCid mylcid;
    // get the PDCP entity for this LCID
    LtePdcpEntity* entity;
    MacNodeId destId;

    if (three_hundred == 0)
    {
        pkt->setBitLength(2400);
        three_hundred = 4;
    }
    else
    {
        pkt->setBitLength(1520);
        three_hundred -= 1;
    }


    if(strcmp(pkt->getName(), "Alert") == 0)
    {
        //AlertPacket* alertpkt = check_and_cast<AlertPacket*>(pkt);
        ipBased_=true;
        retrievedPktId = retrievedPktId+1;
        numberAlertPackets = numberAlertPackets+1;
        emit(alertSentMsg_,numberAlertPackets);

    }
    else
    {
        ipBased_=false;
        retrievedCAMId = retrievedCAMId+1;
    }

    if(ipBased_)
    {

        FlowControlInfo* ipInfo = check_and_cast<FlowControlInfo*>(pkt->removeControlInfo());
        ipInfo->setIpBased(true);

        setTrafficInformation(pkt, ipInfo);
        headerCompress(pkt, ipInfo->getHeaderSize()); // header compression

        IPv4Address destAddr = IPv4Address(ipInfo->getDstAddr());

        // the direction of the incoming connection is a D2D_MULTI one if the application is of the same type,
        // else the direction will be selected according to the current status of the UE, i.e. D2D or UL
        if (destAddr.isMulticast())
        {
            ipInfo->setDirection(D2D_MULTI);

            // assign a multicast group id
            // multicast IP addresses are 224.0.0.0/4.
            // We consider the host part of the IP address (the remaining 28 bits) as identifier of the group,
            // so as it is univocally determined for the whole network
            uint32 address = IPv4Address(ipInfo->getDstAddr()).getInt();
            uint32 mask = ~((uint32)255 << 28);      // 0000 1111 1111 1111
            uint32 groupId = address & mask;
            ipInfo->setMulticastGroupId((int32)groupId);
        }

        else
        {
            // FlowControlInfoNonIp* nonIpInfo = check_and_cast<FlowControlInfoNonIp*>(pkt->removeControlInfo());
            // setTrafficInformation(pkt, nonIpInfo);
            if (binder_->getMacNodeId(destAddr) == 0)
            {
                EV << NOW << " LtePdcpRrcUeD2D::fromDataIn - Destination " << destAddr << " has left the simulation. Delete packet." << endl;
                delete pkt;
                return;
            }

            // This part is required for supporting D2D unicast with dynamic-created modules
            // the first time we see a new destination address, we need to check whether the endpoint
            // is a D2D peer and, eventually, add it to the binder
            const char* destName = (L3AddressResolver().findHostWithAddress(destAddr))->getFullName();
            if (d2dPeeringInit_.find(destName) == d2dPeeringInit_.end() || !d2dPeeringInit_.at(destName))
            {
                MacNodeId d2dPeerId = binder_->getMacNodeId(destAddr);
                binder_->addD2DCapability(nodeId_, d2dPeerId);
                d2dPeeringInit_[destName] = true;
            }

            // set direction based on the destination Id. If the destination can be reached
            // using D2D, set D2D direction. Otherwise, set UL direction
            destId = binder_->getMacNodeId(destAddr);
            ipInfo->setDirection(D2D_MULTI);

            if (binder_->checkD2DCapability(nodeId_, destId))
            {
                // this way, we record the ID of the endpoint even if the connection is in IM
                // this is useful for mode switching
                ipInfo->setD2dTxPeerId(nodeId_);
                ipInfo->setD2dRxPeerId(destId);
            }
            else
            {
                ipInfo->setD2dTxPeerId(0);
                ipInfo->setD2dRxPeerId(0);
            }
        }

        // Cid Request
        EV << NOW << " LtePdcpRrcUeD2D : Received CID request for Traffic [ " << "Source: "
                << IPv4Address(ipInfo->getSrcAddr()) << "@" << ipInfo->getSrcPort()
                << " Destination: " << destAddr << "@" << ipInfo->getDstPort()
                << " , Direction: " << dirToA((Direction)ipInfo->getDirection()) << " ]\n";

        /*
         * Different lcid for different directions of the same flow are assigned.
         * RLC layer will create different RLC entities for different LCIDs
         */

        LogicalCid mylcid;
        if ((mylcid = ht_->find_entry(ipInfo->getSrcAddr(), ipInfo->getDstAddr(),
                ipInfo->getSrcPort(), ipInfo->getDstPort(), ipInfo->getDirection())) == 0xFFFF)
        {
            // LCID not found

            // assign a new LCID to the connection
            mylcid = lcid_++;

            EV << "LtePdcpRrcUeD2D : Connection not found, new CID created with LCID " << mylcid << "\n";

            ht_->create_entry(ipInfo->getSrcAddr(), ipInfo->getDstAddr(),
                    ipInfo->getSrcPort(), ipInfo->getDstPort(), ipInfo->getDirection(), mylcid);
        }

        entity= getEntity(mylcid);

        // get the sequence number for this PDCP SDU.
        // Note that the numbering depends on the entity the packet is associated to.
        unsigned int sno = entity->nextSequenceNumber();

        ipInfo->setSequenceNumber(sno);
        ipInfo->setDuration(1); //Duration as 1s
        ipInfo->setCreationTime(pkt->getCreationTime());
        ipInfo->setPriority(1); // Warning messages have higher priority
        ipInfo->setTraffic(5);
        ipInfo->setPktId(retrievedPktId);
        EV<<"Retrieved packetId: "<<retrievedPktId<<endl;




        // set some flow-related info
        ipInfo->setLcid(mylcid);
        ipInfo->setSourceId(nodeId_);
        if (ipInfo->getDirection() == D2D)
            ipInfo->setDestId(destId);
        else if (ipInfo->getDirection() == D2D_MULTI)
            ipInfo->setDestId(nodeId_);             // destId is meaningless for multicast D2D (we use the id of the source for statistic purposes at lower levels)
        else // UL
            ipInfo->setDestId(getDestId(ipInfo));
        EV << "LtePdcpRrcUeD2D : Assigned Lcid: " << mylcid << "\n";
        EV << "LtePdcpRrcUeD2D : Assigned Node ID: " << nodeId_ << "\n";

        // PDCP Packet creation
        LtePdcpPdu* pdcpPkt = new LtePdcpPdu("LtePdcpPdu");
        pdcpPkt->setByteLength(ipInfo->getRlcType() == UM ? PDCP_HEADER_UM : PDCP_HEADER_AM);
        pdcpPkt->encapsulate(pkt);
        pdcpPkt->setControlInfo(ipInfo);

        EV << "LtePdcp : Preparing to send "
                << lteTrafficClassToA((LteTrafficClass) ipInfo->getTraffic())
                << " traffic\n";
        EV << "LtePdcp : Packet size " << pdcpPkt->getByteLength() << " Bytes\n";
        EV << "LtePdcp : Sending packet " << pdcpPkt->getName() << " on port "
                << (ipInfo->getRlcType() == UM ? "UM_Sap$o\n" : "AM_Sap$o\n");
        setDataArrivalStatus(true);
        // Send message
        send(pdcpPkt, (ipInfo->getRlcType() == UM ? umSap_[OUT] : amSap_[OUT]));
        emit(sentPacketToLowerLayer, pdcpPkt);
    }

    else if(ipBased_==false)
    {
       binder_->BroadcastUeInfo.clear();
        // NonIp flow
        FlowControlInfoNonIp* nonIpInfo = check_and_cast<FlowControlInfoNonIp*>(pkt->removeControlInfo());

        setTrafficInformation(pkt, nonIpInfo);
        long dstAddr = nonIpInfo->getDstAddr();
        destId = binder_->getMacNodeId(dstAddr);

        // Cid Request
        EV << "LtePdcpRrc : Received CID request for Traffic [ " << "Source: "
                << nonIpInfo->getSrcAddr() << " Destination: " << nonIpInfo->getDstAddr() << " ]\n";

        if ((mylcid = nonIpHt_->find_entry(nonIpInfo->getSrcAddr(), nonIpInfo->getDstAddr())) == 0xFFFF)
        {
            // LCID not found
            mylcid = lcid_++;

            EV << "LteRrc : Connection not found, new CID created with LCID " << mylcid << "\n";
            // Non-IP connection table
            nonIpHt_->create_entry(nonIpInfo->getSrcAddr(), nonIpInfo->getDstAddr(), mylcid);
        }

        entity= getEntity(mylcid);

        // get the sequence number for this PDCP SDU.
        // Note that the numbering depends on the entity the packet is associated to.
        unsigned int sno = entity->nextSequenceNumber();

        // set sequence number
        nonIpInfo->setSequenceNumber(sno);

        // set some flow-related info
        nonIpInfo->setLcid(mylcid);
        nonIpInfo->setSourceId(nodeId_);
        nonIpInfo->setPriority(2); //CAMS have lower priority
        nonIpInfo->setTraffic(4);
        nonIpInfo->setCAMId(retrievedCAMId);
        if (nonIpInfo->getDirection() == D2D)
            nonIpInfo->setDestId(destId);
        else if (nonIpInfo->getDirection() == D2D_MULTI)
        {
            nonIpInfo->setDestId(nodeId_);
            //std::map<MacNodeId,inet::Coord> BroadcastUeInfo;
            std::vector<inet::Coord> ueCoords;
            double distance;
            std::vector<UeInfo*>* ueList = binder_->getUeList();
            std::vector<UeInfo*>::iterator itue = ueList->begin();
            int k = 0;

            MacNodeId sourceId = nodeId_;
            EV<<"Source vehicle: "<<sourceId<<endl;
            EV<<"UE list: "<<ueList->size()<<endl;

            if (ueList->size()!=0)
            {
                for (; itue != ueList->end(); ++itue)

                {

                    MacNodeId UeId = (*itue)->id;

                    LtePhyBase* phy = check_and_cast<LtePhyBase*>(getSimulation()->getModule(binder_->getOmnetId(UeId))->getSubmodule("lteNic")->getSubmodule("phy"));
                    inet::Coord uePos = phy->getCoord();
                    binder_->BroadcastUeInfo[UeId]=uePos;
                    ueCoords.push_back(uePos);
                    k=k+1;


                }
            }

            int k1= ueCoords.size();

            EV<<"Number of UEs in simulation: "<<ueCoords.size()<<endl;
            std::map<MacNodeId,inet::Coord>::iterator itb = binder_->BroadcastUeInfo.begin();
            EV<<"BroadcastUeInfo size: "<<binder_->BroadcastUeInfo.size()<<endl;
            inet::Coord sourceCoord =binder_->BroadcastUeInfo.find(sourceId)->second;
            EV<<"Source coordinates: "<<sourceCoord<<endl;

            for(; itb != binder_->BroadcastUeInfo.end(); ++itb)
            {
                distance = itb->second.distance(sourceCoord);

                EV<<"Distance: "<<distance<<endl;
                EV<<"Connected: "<<binder_->isNodeRegisteredInSimlation()<<endl;

                if((distance !=0 && distance<=100) && binder_->isNodeRegisteredInSimlation()==true)
                {
                    EV<<"Sensing neighbours"<<endl;
                    MacNodeId ueid = itb->first;
                    binder_->BroadcastUeInfo[ueid]=itb->second;

                    nonIpInfo->setDestId(ueid);
                }

                else if (distance ==0 || distance > 100)
                {
                    EV<<"EGO vehicle itself"<<endl;
                    //binder_->BroadcastUeInfo.erase(itb);
                    nonIpInfo->setDestId(nodeId_);

                }
                else
                {
                    EV<<"distance: "<<distance <<endl;
                    //throw cRuntimeError("Invalid nodes in the simulation");
                }

            }

            EV<<"BroadcastUeInfo size final : "<<binder_->BroadcastUeInfo.size()<<endl;
            std::map<MacNodeId,inet::Coord>::iterator itf = binder_->BroadcastUeInfo.begin();
            for(; itf != binder_->BroadcastUeInfo.end(); ++itf)
            {
                EV<<"Chosen UE recipients: "<<"NodeId: "<<itf->first<<"Coordinates: "<<itf->second<<endl;
                binder_->addBroadcastUeList(itf->first, itf->second);
            }


        }

        //(we use the id of the source for statistic purposes at lower levels)
        else // UL
            nonIpInfo->setDestId(getDestId(nonIpInfo));


        // PDCP Packet creation
        LtePdcpPdu* pdcpPkt = new LtePdcpPdu("LtePdcpPdu");
        cMessage* dataArrival = new cMessage("Data Arrival");
        pdcpPkt->setByteLength(nonIpInfo->getRlcType() == UM ? PDCP_HEADER_UM : PDCP_HEADER_AM);
        pdcpPkt->encapsulate(pkt);
        pdcpPkt->setControlInfo(nonIpInfo);

        EV << "LtePdcp : Preparing to send "
                << lteTrafficClassToA((LteTrafficClass) nonIpInfo->getTraffic())
                << " traffic\n";
        EV << "LtePdcp : Packet size " << pdcpPkt->getByteLength() << " Bytes\n";
        EV << "LtePdcp : Sending packet " << pdcpPkt->getName() << " on port "
                << (nonIpInfo->getRlcType() == UM ? "UM_Sap$o\n" : "AM_Sap$o\n");
        // Send message
        setDataArrivalStatus(true);
        send(pdcpPkt, (nonIpInfo->getRlcType() == UM ? umSap_[OUT] : amSap_[OUT]));
        send(dataArrival,control_OUT);
        emit(sentPacketToLowerLayer, pdcpPkt);
    }


    else
    {
        throw cRuntimeError("invalid message type");
    }


}


void LtePdcpRrcUeD2D::handleMessage(cMessage* msg)
{
    cPacket* pkt = check_and_cast<cPacket *>(msg);

    // check whether the message is a notification for mode switch
    if (strcmp(pkt->getName(),"D2DModeSwitchNotification") == 0)
    {
        EV << "LtePdcpRrcUeD2D::handleMessage - Received packet " << pkt->getName() << " from port " << pkt->getArrivalGate()->getName() << endl;

        D2DModeSwitchNotification* switchPkt = check_and_cast<D2DModeSwitchNotification*>(pkt);

        // call handler
        pdcpHandleD2DModeSwitch(switchPkt->getPeerId(), switchPkt->getNewMode());

        delete pkt;
    }
    else if (strcmp(pkt->getName(), "CBR") == 0)
    {
        EV << "LtePdcp : Sending packet " << pkt->getName() << " on port DataOut\n";
        // Send message
        //send(pkt, DataPortNonIpOut);
        delete pkt;
        emit(sentPacketToUpperLayer, pkt);
    }
    else
    {
        LtePdcpRrcBase::handleMessage(msg);
    }
}

void LtePdcpRrcUeD2D::pdcpHandleD2DModeSwitch(MacNodeId peerId, LteD2DMode newMode)
{
    EV << NOW << " LtePdcpRrcUeD2D::pdcpHandleD2DModeSwitch - peering with UE " << peerId << " set to " << d2dModeToA(newMode) << endl;

    // add here specific behavior for handling mode switch at the PDCP layer
}


void LtePdcpRrcUeD2D::setDataArrivalStatus(bool dataArrival)
{
    this->dataArrival = dataArrival;
}

void LtePdcpRrcUeD2D::finish()
{
    /*    if (getSimulation()->getSimulationStage() != CTX_FINISH)
        {
            // do this only at deletion of the module during the simulation
            binder_->unregisterNode(nodeId_);
        }*/
}

