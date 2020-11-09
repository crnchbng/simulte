//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#include "stack/mac/layer/LteMacUeD2D.h"
#include "stack/mac/buffer/harq/LteHarqBufferRx.h"
#include "stack/mac/buffer/LteMacQueue.h"
#include "stack/mac/packet/LteSchedulingGrant.h"
#include "stack/mac/scheduler/LteSchedulerUeUl.h"
#include "stack/mac/layer/LteMacEnbD2D.h"
#include "stack/d2dModeSelection/D2DModeSwitchNotification_m.h"
#include "stack/mac/packet/LteRac_m.h"
#include <omnetpp.h>
#include "stack/phy/resources/SidelinkResourceAllocation.h"
#include "stack/mac/packet/SPSResourcePoolMode3.h"
#include "stack/mac/packet/SPSResourcePoolMode4.h"
#include "stack/mac/packet/LteSidelinkGrant.h"

using namespace omnetpp;

Define_Module(LteMacUeD2D);

LteMacUeD2D::LteMacUeD2D() :  LteMacUe()
{
    racD2DMulticastRequested_ = false;
    bsrD2DMulticastTriggered_ = false;
    scheduleListSl_=NULL;
    mode4Grant = NULL;
    mode3Grant=NULL;
    slGrant=NULL;
    preconfiguredTxParams_=NULL;

}

LteMacUeD2D::~LteMacUeD2D()
{
    //delete mode3Grant;
    //delete mode4Grant;

}

void LteMacUeD2D::initialize(int stage)
{
    LteMacUe::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL)
    {
        // check the RLC module type: if it is not "D2D", abort simulation
        lcgScheduler_ = new LteSchedulerUeUl(this);
        lteSchedulerUeSl_ = new LteSchedulerUeSl(this);

        std::string pdcpType = getParentModule()->par("LtePdcpRrcType").stdstringValue();
        cModule* rlc = getParentModule()->getSubmodule("rlc");
        std::string rlcUmType = rlc->par("LteRlcUmType").stdstringValue();
        bool rlcD2dCapable = rlc->par("d2dCapable").boolValue();
        if (rlcUmType.compare("LteRlcUm") != 0 || !rlcD2dCapable)
            throw cRuntimeError("LteMacUeD2D::initialize - %s module found, must be LteRlcUmD2D. Aborting", rlcUmType.c_str());
        if (pdcpType.compare("LtePdcpRrcUeD2D") != 0)
            throw cRuntimeError("LteMacUeD2D::initialize - %s module found, must be LtePdcpRrcUeD2D. Aborting", pdcpType.c_str());

        rcvdD2DModeSwitchNotification_ = registerSignal("rcvdD2DModeSwitchNotification");
    }
    if (stage == inet::INITSTAGE_NETWORK_LAYER_3)
    {
        MacNodeId enbId_ = getAncestorPar("masterId");
        LtePhyBase* enb_ = check_and_cast<LtePhyBase*>(
                getSimulation()->getModule(binder_->getOmnetId(enbId_))->getSubmodule("lteNic")->getSubmodule("phy"));
        inet::Coord enbCoord = enb_->getCoord();
        EV<<"Coordinates of eNB stage 8: "<<enbCoord<<endl;

        LtePhyBase* ue_ = check_and_cast<LtePhyBase*>(
                getSimulation()->getModule(binder_->getOmnetId(nodeId_))->getSubmodule("lteNic")->getSubmodule("phy"));
        inet::Coord ueCoord = ue_->getCoord();

        double ueDistanceFromEnb =ue_->getCoord().distance(enbCoord);

        if (ueDistanceFromEnb<200)
        {
            EV<<"Attaching UE stage 8 located at a distance of: "<<ueDistanceFromEnb<<endl;
            // get parameters
            usePreconfiguredTxParams_ = par("usePreconfiguredTxParams");
            preconfiguredTxParams_ = getPreconfiguredTxParams();

            // get the reference to the eNB
            enbmac_ = check_and_cast<LteMacEnbD2D*>(getSimulation()->getModule(binder_->getOmnetId(cellId_))->getSubmodule("lteNic")->getSubmodule("mac"));

            LteAmc *amc = check_and_cast<LteMacEnbD2D *>(getSimulation()->getModule(binder_->getOmnetId(cellId_))->getSubmodule("lteNic")->getSubmodule("mac"))->getAmc();
            amc->attachUser(nodeId_, D2D);
        }

    }
}
void LteMacUeD2D::handleMessage(cMessage* msg)
{
    EV<<"LteMacUeD2D::handleMessage: "<<msg->getName()<<endl;

    if (msg->isSelfMessage())
    {
        if (strcmp(msg->getName(), "flushHarqMsg") == 0)
        {
            EV<<"Calling flushHarq SC: "<<getSchedulingGrant()<<endl;
            SidelinkConfiguration* slConfig = check_and_cast<SidelinkConfiguration*>(getParentModule()->getSubmodule("mode4config"));
            slConfig->flushHarqBuffers(harqTxBuffers_, getSchedulingGrant());

            delete msg;
            return;
        }

        else
        {

            LteMacUe::handleMessage(msg);
        }
        return;
    }

    cPacket* pkt = check_and_cast<cPacket *>(msg);
    cGate* incoming = pkt->getArrivalGate();



    if (strcmp(pkt->getName(), "CSRs")== 0)
    {
        //throw cRuntimeError("MAC error CSR");
        SPSResourcePool* candidatesPacket = check_and_cast<SPSResourcePool *>(pkt);
        SidelinkConfiguration* slConfig = check_and_cast<SidelinkConfiguration*>(getParentModule()->getSubmodule("mode4config"));
        slConfig->macHandleSps(candidatesPacket->getCSRs(), rrcCurrentState);
        mode4Grant = slConfig->getSidelinkGrant();

        //Send message to PHY so that it can keep this and check for next time
        SPSResourcePool* csrsprevious = new  SPSResourcePool("CSRsPrevious");
        csrsprevious->setAllocatedBlocksScIandDataPrevious(slConfig->getAllocatedBlocksSCIandData());
        send(csrsprevious,down_[OUT]);
        return;
    }

    if (strcmp(pkt->getName(), "CBR")== 0)
    {

        SidelinkConfiguration* slConfig = check_and_cast<SidelinkConfiguration*>(getParentModule()->getSubmodule("mode4config"));
        slConfig->handleMessage(pkt);
        return;
    }



    if (incoming == down_[IN])
    {

        UserControlInfo *userInfo = check_and_cast<UserControlInfo *>(pkt->getControlInfo());
        if (userInfo->getFrameType() == D2DMODESWITCHPKT)
        {

            EV << "LteMacUeD2D::handleMessage - Received packet " << pkt->getName() <<
                    " from port " << pkt->getArrivalGate()->getName() << endl;

            // message from PHY_to_MAC gate (from lower layer)
            emit(receivedPacketFromLowerLayer, pkt);

            // call handler
            macHandleD2DModeSwitch(pkt);

            return;
        }
        if (userInfo->getFrameType()==RACPKT)
        {
            EV<<"Received packet: "<<pkt->getName()<<endl;
            EV<<"UE requests for mode 3 Grant from eNodeB"<<endl;
            LteSidelinkGrant* mode3Grant = new LteSidelinkGrant("Mode3GrantRequest");
            UserControlInfo* uinfo = new UserControlInfo();
            uinfo->setSourceId(getMacNodeId());
            uinfo->setDestId(getMacCellId());

            uinfo->setFrameType(MODE3GRANTREQUEST);
            mode3Grant->setControlInfo(uinfo);
            sendLowerPackets(mode3Grant);
            return;
        }

        if (userInfo->getFrameType()==CSRPKT)
        {

            SPSResourcePoolMode3* csrpkt = check_and_cast< SPSResourcePoolMode3*>(pkt);
            mode3Grant = csrpkt->getMode3grant();
            EV<<"Transmit block size: "<<mode3Grant->getTransmitBlockSize()<<endl;

        }


        //Receiving SCI

    }
    else if (incoming == up_[IN])
    {

        if (strcmp(pkt->getName(), "newDataPkt")== 0)
        {

            EV<<"RRC state: "<<rrcCurrentState<<endl;
            if (rrcCurrentState=="RRC_IDLE")
            {
                LteMacUe::handleUpperMessage(pkt);

                SidelinkConfiguration* slConfig = check_and_cast<SidelinkConfiguration*>(getParentModule()->getSubmodule("mode4config"));
                slConfig->handleMessage(msg);
                EV<<"LteMacUeD2D received packet of bit length: "<<pkt->getBitLength()<<endl;
            }

            if (rrcCurrentState=="RRC_CONN" || rrcCurrentState=="RRC_INACTIVE")
            {

                LteMacUe::handleUpperMessage(pkt); //Data pkt waits in the buffer until it receives resources from eNodeB
                if(ipBased==false)
                {
                    FlowControlInfoNonIp* lteInfo = check_and_cast<FlowControlInfoNonIp*>(pkt->removeControlInfo());
                    DataArrival* dataArrival = new DataArrival("DataArrival");
                    UserControlInfo* uinfo = new UserControlInfo();
                    uinfo->setSourceId(getMacNodeId());
                    uinfo->setDestId(getMacCellId());
                    uinfo->setPktId(lteInfo->getPktId());
                    dataArrival->setDuration(lteInfo ->getDuration());
                    dataArrival->setCreationTime(lteInfo ->getCreationTime().dbl());
                    dataArrival->setPriority(lteInfo ->getPriority());

                    dataArrival->setDataSize(pkt->getBitLength());
                    uinfo->setFrameType(DATAARRIVAL);
                    uinfo->setIpBased(ipBased);

                    dataArrival->setControlInfo(uinfo);
                    sendLowerPackets(dataArrival);
                }
                if(ipBased==true)
                {

                    FlowControlInfo* lteInfo = check_and_cast<FlowControlInfo*>(pkt->removeControlInfo());
                    DataArrival* dataArrival = new DataArrival("DataArrival");
                    UserControlInfo* uinfo = new UserControlInfo();
                    uinfo->setSourceId(getMacNodeId());
                    uinfo->setDestId(getMacCellId());
                    uinfo->setPktId(lteInfo->getPktId());

                    dataArrival->setDuration(0.01);
                    dataArrival->setCreationTime(NOW.dbl());
                    dataArrival->setPriority(0);

                    dataArrival->setDataSize(pkt->getBitLength());
                    uinfo->setFrameType(DATAARRIVAL);
                    uinfo->setIpBased(ipBased);
                    dataArrival->setControlInfo(uinfo);
                    sendLowerPackets(dataArrival);

                }


            }

            //sra->calculateNumberResourceBlocks(pkt->getBitLength());
        }
        if(strcmp(pkt->getName(), "lteRlcFragment")== 0)
        {
            LteMacUe::handleUpperMessage(pkt);

            return;
        }



    }

    else if(strcmp(msg->getName(), "RRCStateChange")== 0)
    {
        RRCStateChange* rrcstate = check_and_cast<RRCStateChange*> (msg);
        rrcCurrentState = rrcstate->getState();
        EV<<"RRC state: "<<rrcCurrentState<<endl;
        send(rrcstate,down_[OUT]);
        return;
    }


    else
    {
        EV<<"Received message: "<<pkt->getName()<<endl;

        LteMacUe::handleMessage(msg);
    }
}

//Function for create only a BSR for the eNB
LteMacPdu* LteMacUeD2D::makeBsr(int size){

    UserControlInfo* uinfo = new UserControlInfo();
    uinfo->setSourceId(getMacNodeId());
    uinfo->setDestId(getMacCellId());
    uinfo->setDirection(UL);
    uinfo->setUserTxParams(schedulingGrant_->getUserTxParams()->dup());
    LteMacPdu* macPkt = new LteMacPdu("LteMacPdu");
    macPkt->setHeaderLength(MAC_HEADER);
    macPkt->setControlInfo(uinfo);
    macPkt->setTimestamp(NOW);
    MacBsr* bsr = new MacBsr();
    bsr->setTimestamp(simTime().dbl());
    bsr->setSize(size);
    macPkt->pushCe(bsr);
    bsrTriggered_ = false;
    EV << "LteMacUeD2D::makeBsr() - BSR with size " << size << "created" << endl;
    return macPkt;
}

void LteMacUeD2D::macPduMake(MacCid cid)
{
    EV<<"LteMacUeD2D::macPduMake"<<endl;

    int64 size = 0;

    macPduList_.clear();

    // In a D2D communication if BSR was created above this part isn't executed
    // Build a MAC PDU for each scheduled user on each codeword
    LteMacScheduleList::const_iterator it;
    for (it = scheduleList_->begin(); it != scheduleList_->end(); it++)
    {
        LteMacPdu* macPkt;
        cPacket* pkt;

        MacCid destCid = it->first.first;
        Codeword cw = it->first.second;

        EV<<"Destination Cid: "<<destCid<<endl;

        // get the direction (UL/D2D/D2D_MULTI) and the corresponding destination ID
        LteControlInfo* lteInfo = &(connDesc_.at(destCid));
        MacNodeId destId = lteInfo->getDestId();
        Direction dir = (Direction)lteInfo->getDirection();

        std::pair<MacNodeId, Codeword> pktId = std::pair<MacNodeId, Codeword>(destId, cw);
        unsigned int sduPerCid = it->second;

        MacPduList::iterator pit = macPduList_.find(pktId);

        if (sduPerCid == 0)
        {
            continue;
        }

        // No packets for this user on this codeword
        if (pit == macPduList_.end())
        {
            // Always goes here because of the macPduList_.clear() at the beginning
            // Build the Control Element of the MAC PDU
            UserControlInfo* uinfo = new UserControlInfo();
            uinfo->setSourceId(getMacNodeId());
            uinfo->setDestId(destId);
            uinfo->setLcid(MacCidToLcid(destCid));
            uinfo->setDirection(dir);
            uinfo->setLcid(MacCidToLcid(SHORT_BSR));

            uinfo->setIpBased(ipBased);
            uinfo->setPktId(transmissionPid);
            uinfo->setCAMId(transmissionCAMId);
            EV<<"Packet ID: "<<transmissionPid<<endl;

            // First translate MCS to CQI
            LteSidelinkGrant* sidelinkgrant = getSchedulingGrant();
            EV<<"usePreconfiguredTxParams: "<<usePreconfiguredTxParams_<<endl;

            /*            if (usePreconfiguredTxParams_)
            {
                //UserTxParams* userTxParams = preconfiguredTxParams_;
                EV<<"Preconfigured params: "<<preconfiguredTxParams_->dup()<<endl;

                throw cRuntimeError("LteMacPduMake()");
                uinfo->setUserTxParams(preconfiguredTxParams_->dup());

                sidelinkgrant->setUserTxParams(uinfo->getUserTxParams());
            }
            else*/
            uinfo->setUserTxParams(sidelinkgrant->getUserTxParams());

            // Create a PDU
            macPkt = new LteMacPdu("LteMacPdu");
            macPkt->setHeaderLength(MAC_HEADER);
            macPkt->setControlInfo(uinfo);
            macPkt->setTimestamp(NOW);
            macPduList_[pktId] = macPkt;
            EV<<"SduperCid: "<<sduPerCid<<endl;
        }
        else
        {
            // Never goes here because of the macPduList_.clear() at the beginning
            macPkt = pit->second;
        }

        while (sduPerCid > 0)
        {
            // Add SDU to PDU
            // Find Mac Pkt

            bool check = mbuf_.find(destCid) == mbuf_.end();

            EV<<"Check condition: "<<check<<endl;


            if (mbuf_.find(destCid) == mbuf_.end())
            {
                throw cRuntimeError("Unable to find mac buffer for cid %d", destCid);
            }

            if (mbuf_[destCid]->empty())
                throw cRuntimeError("Empty buffer for cid %d, while expected SDUs were %d", destCid, sduPerCid);

            pkt = mbuf_[destCid]->popFront();

            // multicast support
            // this trick gets the group ID from the MAC SDU and sets it in the MAC PDU
            int32 groupId = check_and_cast<LteControlInfo*>(pkt->getControlInfo())->getMulticastGroupId();
            if (groupId >= 0) // for unicast, group id is -1
                check_and_cast<LteControlInfo*>(macPkt->getControlInfo())->setMulticastGroupId(groupId);

            drop(pkt);

            macPkt->pushSdu(pkt);
            sduPerCid--;
        }

        // consider virtual buffers to compute BSR size
        size += macBuffers_[destCid]->getQueueOccupancy();

        if (size > 0)
        {
            // take into account the RLC header size
            if (connDesc_[destCid].getRlcType() == UM)
                size += RLC_HEADER_UM;
            else if (connDesc_[destCid].getRlcType() == AM)
                size += RLC_HEADER_AM;
        }
    }

    // Put MAC PDUs in H-ARQ buffers
    MacPduList::iterator pit;
    for (pit = macPduList_.begin(); pit != macPduList_.end(); pit++)
    {
        MacNodeId destId = pit->first.first;
        Codeword cw = pit->first.second;
        // Check if the HarqTx buffer already exists for the destId
        // Get a reference for the destId TXBuffer
        LteHarqBufferTx* txBuf;
        HarqTxBuffers::iterator hit = harqTxBuffers_.find(destId);
        if ( hit != harqTxBuffers_.end() )
        {
            // The tx buffer already exists
            txBuf = hit->second;
        }
        else
        {
            // The tx buffer does not exist yet for this mac node id, create one
            LteHarqBufferTx* hb;
            // FIXME: hb is never deleted
            UserControlInfo* info = check_and_cast<UserControlInfo*>(pit->second->getControlInfo());
            if (info->getDirection() == UL)
                hb = new LteHarqBufferTx((unsigned int) ENB_TX_HARQ_PROCESSES, this, (LteMacBase*) getMacByMacNodeId(destId));
            else // D2D or D2D_MULTI
                hb = new LteHarqBufferTxD2D((unsigned int) ENB_TX_HARQ_PROCESSES, this, (LteMacBase*) getMacByMacNodeId(destId));
            harqTxBuffers_[destId] = hb;
            txBuf = hb;
        }

        // search for an empty unit within current harq process
        UnitList txList = txBuf->getEmptyUnits(currentHarq_);
        EV << "LteMacUeRealisticD2D::macPduMake - [Used Acid=" << (unsigned int)txList.first << "] , [curr=" << (unsigned int)currentHarq_ << "]" << endl;

        //Get a reference of the LteMacPdu from pit pointer (extract Pdu from the MAP)
        LteMacPdu* macPkt = pit->second;

        EV << "LteMacUeRealisticD2D: pduMaker created PDU: " << macPkt->info() << endl;

        if (txList.second.empty())
        {
            EV << "LteMacUeRealisticD2D() : no available process for this MAC pdu in TxHarqBuffer" << endl;
            delete macPkt;
        }
        else
        {
            //Insert PDU in the Harq Tx Buffer
            //txList.first is the acid
            txBuf->insertPdu(txList.first,cw, macPkt);
        }
    }


}



void LteMacUeD2D::macHandleGrant(cPacket* pkt)
{
    EV << NOW << " LteMacUeD2D::macHandleGrant - UE [" << nodeId_ << "] - Grant received " << endl;

    // delete old grant
    LteSchedulingGrant* grant = check_and_cast<LteSchedulingGrant*>(pkt);

    //Codeword cw = grant->getCodeword();

    if (schedulingGrant_!=NULL)
    {
        delete schedulingGrant_;
        schedulingGrant_ = NULL;
    }

    // store received grant
    schedulingGrant_=grant;

    if (grant->getPeriodic())
    {
        periodCounter_=grant->getPeriod();
        expirationCounter_=grant->getExpiration();
    }

    EV << NOW << "Node " << nodeId_ << " received grant of blocks " << grant->getTotalGrantedBlocks()
                                                                                                                                                                                                                                       << ", bytes " << grant->getGrantedCwBytes(0) <<" Direction: "<<dirToA(grant->getDirection()) << endl;

    // clearing pending RAC requests
    racRequested_=false;
    racD2DMulticastRequested_=false;
}

void LteMacUeD2D::checkRAC()
{

    EV << NOW << " LteMacUeD2D::checkRAC , Ue  " << nodeId_ << ", racTimer : " << racBackoffTimer_ << " maxRacTryOuts : " << maxRacTryouts_
            << ", raRespTimer:" << raRespTimer_ << endl;

    if (racBackoffTimer_>0)
    {
        racBackoffTimer_--;
        return;
    }

    if(raRespTimer_>0)
    {
        // decrease RAC response timer
        raRespTimer_--;
        EV << NOW << " LteMacUeD2D::checkRAC - waiting for previous RAC requests to complete (timer=" << raRespTimer_ << ")" << endl;
        return;
    }

    // Avoids double requests whithin same TTI window
    if (racRequested_)
    {
        EV << NOW << " LteMacUeD2D::checkRAC - double RAC request" << endl;
        racRequested_=false;
        return;
    }
    if (racD2DMulticastRequested_)
    {
        EV << NOW << " LteMacUeD2D::checkRAC - double RAC request" << endl;
        racD2DMulticastRequested_=false;
        return;
    }

    bool trigger=false;
    bool triggerD2DMulticast=false;

    LteMacBufferMap::const_iterator it;

    for (it = macBuffers_.begin(); it!=macBuffers_.end();++it)
    {
        if (!(it->second->isEmpty()))
        {
            MacCid cid = it->first;
            if (connDesc_.at(cid).getDirection() == D2D_MULTI)
                triggerD2DMulticast = true;
            else
                trigger = true;
            break;
        }
    }

    if (!trigger && !triggerD2DMulticast)
        EV << NOW << "Ue " << nodeId_ << ",RAC aborted, no data in queues " << endl;

    if ((racRequested_=trigger) || (racD2DMulticastRequested_=triggerD2DMulticast))
    {
        LteRac* racReq = new LteRac("RacRequest");
        UserControlInfo* uinfo = new UserControlInfo();
        uinfo->setSourceId(getMacNodeId());
        uinfo->setDestId(getMacCellId());
        uinfo->setDirection(UL);
        uinfo->setFrameType(RACPKT);
        racReq->setControlInfo(uinfo);

        sendLowerPackets(racReq);

        EV << NOW << " Ue  " << nodeId_ << " cell " << cellId_ << " ,RAC request sent to PHY " << endl;

        // wait at least  "raRespWinStart_" TTIs before another RAC request
        raRespTimer_ = raRespWinStart_;
        EV<<"Wait for next RAC till: "<<raRespTimer_ <<endl;

    }

}

void LteMacUeD2D::macHandleRac(cPacket* pkt)
{
    LteRac* racPkt = check_and_cast<LteRac*>(pkt);

    if (racPkt->getSuccess())
    {
        EV << "LteMacUeD2D::macHandleRac - Ue " << nodeId_ << " won RAC" << endl;
        // is RAC is won, BSR has to be sent
        if (racD2DMulticastRequested_)
            bsrD2DMulticastTriggered_=true;
        else
            bsrTriggered_ = true;

        // reset RAC counter
        currentRacTry_=0;
        //reset RAC backoff timer
        racBackoffTimer_=0;
    }
    else
    {
        // RAC has failed
        if (++currentRacTry_ >= maxRacTryouts_)
        {
            EV << NOW << " Ue " << nodeId_ << ", RAC reached max attempts : " << currentRacTry_ << endl;
            // no more RAC allowed
            //! TODO flush all buffers here
            //reset RAC counter
            currentRacTry_=0;
            //reset RAC backoff timer
            racBackoffTimer_=0;
        }
        else
        {
            // recompute backoff timer
            racBackoffTimer_= uniform(minRacBackoff_,maxRacBackoff_);
            EV << NOW << " Ue " << nodeId_ << " RAC attempt failed, backoff extracted : " << racBackoffTimer_ << endl;
        }
    }
    delete racPkt;
}



void LteMacUeD2D::handleSelfMessage()
{

    EV << "----- UE MAIN LOOP -----" << endl;

    // extract pdus from all harqrxbuffers and pass them to unmaker
    HarqRxBuffers::iterator hit = harqRxBuffers_.begin();
    HarqRxBuffers::iterator het = harqRxBuffers_.end();
    LteMacPdu *pdu = NULL;
    std::list<LteMacPdu*> pduList;

    for (; hit != het; ++hit)
    {
        pduList=hit->second->extractCorrectPdus();
        while (! pduList.empty())
        {
            pdu=pduList.front();
            pduList.pop_front();
            macPduUnmake(pdu);
        }
    }

    EV << NOW << "LteMacVUeMode4::handleSelfMessage " << nodeId_ << " - HARQ process " << (unsigned int)currentHarq_ << endl;

    // updating current HARQ process for next TTI

    //unsigned char currentHarq = currentHarq_;

    // no grant available - if user has backlogged data, it will trigger scheduling request
    // no harq counter is updated since no transmission is sent.

    LteSidelinkGrant* grant = new  LteSidelinkGrant();
    if (rrcCurrentState == "RRC_CONN" ||rrcCurrentState == "RRC_INACTIVE" )
    {
        grant = mode3Grant;

    }

    if (rrcCurrentState == "RRC_IDLE")
    {
        grant = mode4Grant;

    }
    EV<<"Scheduling Grant: "<<grant<<endl;
    setSchedulingGrant(grant);
    if (grant == NULL)
    {
        EV << NOW << " LteMacVUeMode4::handleSelfMessage " << nodeId_ << " NO configured grant" << endl;

        // No configured Grant simply continue
    }
    else if (grant->getPeriodic() && grant->getStartTime() <= NOW)
    {
        EV<<"Test 1a"<<endl;
        // Periodic checks
        if(--expirationCounter_ == grant->getPeriod())
        {
            EV<<"Test 1"<<endl;
            // Gotten to the point of the final tranmission must determine if we reselect or not.
            double randomReReserve = dblrand(1);
            if (randomReReserve > slConfig->probResourceKeep_)
            {
                EV<<"Test 2"<<endl;
                int expiration = intuniform(5, 15, 3);
                grant -> setResourceReselectionCounter(expiration);
                grant -> setFirstTransmission(true);
                expirationCounter_ = expiration * grant->getPeriod();
            }
        }
        if (--periodCounter_>0 && !grant->getFirstTransmission())
        {
            EV<<"Test 3"<<endl;
            return;
        }
        else if (expirationCounter_ > 0)
        {
            // resetting grant period
            EV<<"Test 4"<<endl;
            periodCounter_=grant->getPeriod();
            // this is periodic grant TTI - continue with frame sending
        }
        else if (expirationCounter_ <= 0)
        {
            EV<<"Test 5"<<endl;
            emit(slConfig->grantBreak, 1);
            grant->setExpiration(0);
            slConfig->expiredGrant_ = true;
        }
    }
    bool requestSdu = false;

    if (grant!=NULL && grant->getStartTime() <= NOW) // if a grant is configured
    {
        EV<<"Test 6"<<endl;
        transmissionPid=grant->getPacketId();
        transmissionCAMId = grant->getCamId();
        if (grant->getFirstTransmission())
        {
            EV<<"Test 7"<<endl;
            grant->setFirstTransmission(false);
        }
        if(!firstTx)
        {
            EV << "\t currentHarq_ counter initialized " << endl;
            firstTx=true;
            // the eNb will receive the first pdu in 2 TTI, thus initializing acid to 0
            //            currentHarq_ = harqRxBuffers_.begin()->second->getProcesses() - 2;
            currentHarq_ = UE_TX_HARQ_PROCESSES - 2;
        }


        EV << NOW << " LteMacVUeMode4::handleSelfMessage " << nodeId_ << " entered scheduling" << endl;

        bool retx = false;
        bool availablePdu = false;

        HarqTxBuffers::iterator it2;
        LteHarqBufferTx * currHarq;
        for(it2 = harqTxBuffers_.begin(); it2 != harqTxBuffers_.end(); it2++)
        {
            EV << "\t Looking for retx in acid " << (unsigned int)currentHarq_ << endl;
            currHarq = it2->second;

            // check if the current process has unit ready for retx
            retx = currHarq->getProcess(currentHarq_)->hasReadyUnits();
            CwList cwListRetx = currHarq->getProcess(currentHarq_)->readyUnitsIds();

            if (it2->second->isSelected())
            {
                LteHarqProcessTx* selectedProcess = it2->second->getSelectedProcess();
                // Ensure that a pdu is not already on the HARQ buffer awaiting sending.
                if (selectedProcess != NULL)
                {
                    for (int cw=0; cw<MAX_CODEWORDS; cw++)
                    {
                        if (selectedProcess->getPduLength(cw) != 0)
                        {
                            availablePdu = true;
                        }
                    }
                }
            }

            EV << "\t [process=" << (unsigned int)currentHarq_ << "] , [retx=" << ((retx)?"true":"false")
                                                               << "] , [n=" << cwListRetx.size() << "]" << endl;

            // if a retransmission is needed
            if(retx)
            {
                UnitList signal;
                signal.first=currentHarq_;
                signal.second = cwListRetx;
                currHarq->markSelected(signal,schedulingGrant_->getUserTxParams()->getLayers().size());
            }
        }
        // if no retx is needed, proceed with normal scheduling
        // TODO: This may yet be changed to appear after MCS selection, issue is that if you pick max then you might get more sdus then you want
        // Basing it on the previous mcs value is at least more realistic as to the size of the pdu you will get.
        if(!retx && !availablePdu)
        {
            scheduleList_= lteSchedulerUeSl_->schedule(grant);
            bool sent = macSduRequest(grant,scheduleList_);

            if (!sent)
            {
                // no data to send, but if bsrTriggered is set, send a BSR
                macPduMake();
            }

            requestSdu = sent;
        }
        // Message that triggers flushing of Tx H-ARQ buffers for all users
        // This way, flushing is performed after the (possible) reception of new MAC PDUs
        cMessage* flushHarqMsg = new cMessage("flushHarqMsg");
        flushHarqMsg->setSchedulingPriority(1);        // after other messages
        scheduleAt(NOW, flushHarqMsg);
    }
    //============================ DEBUG ==========================
    HarqTxBuffers::iterator it;

    EV << "\n htxbuf.size " << harqTxBuffers_.size() << endl;

    int cntOuter = 0;
    int cntInner = 0;
    for(it = harqTxBuffers_.begin(); it != harqTxBuffers_.end(); it++)
    {
        LteHarqBufferTx* currHarq = it->second;
        BufferStatus harqStatus = currHarq->getBufferStatus();
        BufferStatus::iterator jt = harqStatus.begin(), jet= harqStatus.end();

        EV_DEBUG << "\t cicloOuter " << cntOuter << " - bufferStatus.size=" << harqStatus.size() << endl;
        for(; jt != jet; ++jt)
        {
            EV_DEBUG << "\t\t cicloInner " << cntInner << " - jt->size=" << jt->size()
                                                               << " - statusCw(0/1)=" << jt->at(0).second << "/" << jt->at(1).second << endl;
        }
    }
    //======================== END DEBUG ==========================

    unsigned int purged =0;
    // purge from corrupted PDUs all Rx H-HARQ buffers
    for (hit= harqRxBuffers_.begin(); hit != het; ++hit)
    {
        // purge corrupted PDUs only if this buffer is for a DL transmission. Otherwise, if you
        // purge PDUs for D2D communication, also "mirror" buffers will be purged
        if (hit->first == cellId_)
            purged += hit->second->purgeCorruptedPdus();
    }
    EV << NOW << " LteMacVUeMode4::handleSelfMessage Purged " << purged << " PDUS" << endl;

    if (!requestSdu)
    {
        // update current harq process id
        currentHarq_ = (currentHarq_+1) % harqProcesses_;
    }

    EV << "--- END UE MAIN LOOP ---" << endl;

}


UserTxParams* LteMacUeD2D::getPreconfiguredTxParams()
{
    UserTxParams* txParams = new UserTxParams();

    // default parameters for D2D
    txParams->isSet() = true;
    txParams->writeTxMode(TRANSMIT_DIVERSITY);
    Rank ri = 1;                                              // rank for TxD is one
    txParams->writeRank(ri);
    txParams->writePmi(intuniform(1, pow(ri, (double) 2)));   // taken from LteFeedbackComputationRealistic::computeFeedback

    Cqi cqi = par("d2dCqi");
    if (cqi < 0 || cqi > 15)
        throw cRuntimeError("LteMacUeD2D::getPreconfiguredTxParams - CQI %s is not a valid value. Aborting", cqi);
    txParams->writeCqi(std::vector<Cqi>(1,cqi));

    BandSet b;
    for (Band i = 0; i < getCellInfo(nodeId_)->getNumBands(); ++i) b.insert(i);

    RemoteSet antennas;
    antennas.insert(MACRO);
    txParams->writeAntennas(antennas);

    return txParams;
}

void LteMacUeD2D::macHandleD2DModeSwitch(cPacket* pkt)
{
    EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - Start" << endl;

    // all data in the MAC buffers of the connection to be switched are deleted

    D2DModeSwitchNotification* switchPkt = check_and_cast<D2DModeSwitchNotification*>(pkt);
    bool txSide = switchPkt->getTxSide();
    MacNodeId peerId = switchPkt->getPeerId();
    LteD2DMode newMode = switchPkt->getNewMode();
    LteD2DMode oldMode = switchPkt->getOldMode();
    UserControlInfo* uInfo = check_and_cast<UserControlInfo*>(pkt->removeControlInfo());
    if (txSide)
    {
        emit(rcvdD2DModeSwitchNotification_,(long)1);

        Direction newDirection = (newMode == DM) ? D2D : UL;
        Direction oldDirection = (oldMode == DM) ? D2D : UL;

        // find the correct connection involved in the mode switch
        MacCid cid;
        LteControlInfo* lteInfo = NULL;
        std::map<MacCid, LteControlInfo>::iterator it = connDesc_.begin();
        for (; it != connDesc_.end(); ++it)
        {
            cid = it->first;
            lteInfo = check_and_cast<LteControlInfo*>(&(it->second));

            if (lteInfo->getD2dRxPeerId() == peerId && (Direction)lteInfo->getDirection() == oldDirection)
            {
                EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - found old connection with cid " << cid << ", erasing buffered data" << endl;
                if (oldDirection != newDirection)
                {
                    if (switchPkt->getClearRlcBuffer())
                    {
                        EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - erasing buffered data" << endl;

                        // empty virtual buffer for the selected cid
                        LteMacBufferMap::iterator macBuff_it = macBuffers_.find(cid);
                        if (macBuff_it != macBuffers_.end())
                        {
                            while (!(macBuff_it->second->isEmpty()))
                                macBuff_it->second->popFront();
                            delete macBuff_it->second;
                            macBuffers_.erase(macBuff_it);
                        }

                        // empty real buffer for the selected cid (they should be already empty)
                        LteMacBuffers::iterator mBuf_it = mbuf_.find(cid);
                        if (mBuf_it != mbuf_.end())
                        {
                            while (mBuf_it->second->getQueueLength() > 0)
                            {
                                cPacket* pdu = mBuf_it->second->popFront();
                                delete pdu;
                            }
                            delete mBuf_it->second;
                            mbuf_.erase(mBuf_it);
                        }
                    }

                    if (switchPkt->getInterruptHarq())
                    {
                        EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - interrupting H-ARQ processes" << endl;

                        // interrupt H-ARQ processes for SL
                        unsigned int id = peerId;
                        HarqTxBuffers::iterator hit = harqTxBuffers_.find(id);
                        if (hit != harqTxBuffers_.end())
                        {
                            for (int proc = 0; proc < (unsigned int) UE_TX_HARQ_PROCESSES; proc++)
                            {
                                hit->second->forceDropProcess(proc);
                            }
                        }

                        // interrupt H-ARQ processes for UL
                        id = getMacCellId();
                        hit = harqTxBuffers_.find(id);
                        if (hit != harqTxBuffers_.end())
                        {
                            for (int proc = 0; proc < (unsigned int) UE_TX_HARQ_PROCESSES; proc++)
                            {
                                hit->second->forceDropProcess(proc);
                            }
                        }
                    }
                }

                // abort BSR requests
                bsrTriggered_ = false;

                D2DModeSwitchNotification* switchPkt_dup = switchPkt->dup();
                switchPkt_dup->setControlInfo(lteInfo->dup());
                switchPkt_dup->setOldConnection(true);
                sendUpperPackets(switchPkt_dup);

                if (oldDirection != newDirection && switchPkt->getClearRlcBuffer())
                {
                    EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - clearing LCG map" << endl;

                    // remove entry from lcgMap
                    LcgMap::iterator lt = lcgMap_.begin();
                    for (; lt != lcgMap_.end(); )
                    {
                        if (lt->second.first == cid)
                        {
                            lcgMap_.erase(lt++);
                        }
                        else
                        {
                            ++lt;
                        }
                    }
                }
                EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - send switch signal to the RLC TX entity corresponding to the old mode, cid " << cid << endl;
            }
            else if (lteInfo->getD2dRxPeerId() == peerId && (Direction)lteInfo->getDirection() == newDirection)
            {
                EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - send switch signal to the RLC TX entity corresponding to the new mode, cid " << cid << endl;
                if (oldDirection != newDirection)
                {
                    D2DModeSwitchNotification* switchPkt_dup = switchPkt->dup();
                    switchPkt_dup->setOldConnection(false);
                    switchPkt_dup->setControlInfo(lteInfo->dup());
                    switchPkt_dup->setSchedulingPriority(1);        // always after the old mode
                    sendUpperPackets(switchPkt_dup);
                }
            }
        }
    }
    else   // rx side
    {
        Direction newDirection = (newMode == DM) ? D2D : DL;
        Direction oldDirection = (oldMode == DM) ? D2D : DL;

        // find the correct connection involved in the mode switch
        MacCid cid;
        LteControlInfo* lteInfo = NULL;
        std::map<MacCid, LteControlInfo>::iterator it = connDescIn_.begin();
        for (; it != connDescIn_.end(); ++it)
        {
            cid = it->first;
            lteInfo = check_and_cast<LteControlInfo*>(&(it->second));
            if (lteInfo->getD2dTxPeerId() == peerId && (Direction)lteInfo->getDirection() == oldDirection)
            {
                EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - found old connection with cid " << cid << ", send signal to the RLC RX entity" << endl;
                if (oldDirection != newDirection)
                {
                    if (switchPkt->getInterruptHarq())
                    {
                        // interrupt H-ARQ processes for SL
                        unsigned int id = peerId;
                        HarqRxBuffers::iterator hit = harqRxBuffers_.find(id);
                        if (hit != harqRxBuffers_.end())
                        {
                            for (unsigned int proc = 0; proc < (unsigned int) UE_RX_HARQ_PROCESSES; proc++)
                            {
                                unsigned int numUnits = hit->second->getProcess(proc)->getNumHarqUnits();
                                for (unsigned int i=0; i < numUnits; i++)
                                {
                                    hit->second->getProcess(proc)->purgeCorruptedPdu(i); // delete contained PDU
                                    hit->second->getProcess(proc)->resetCodeword(i);     // reset unit
                                }
                            }
                        }

                        // clear mirror H-ARQ buffers
                        enbmac_->deleteHarqBuffersMirrorD2D(peerId, nodeId_);

                        // notify that this UE is switching during this TTI
                        resetHarq_[peerId] = NOW;
                    }

                    D2DModeSwitchNotification* switchPkt_dup = switchPkt->dup();
                    switchPkt_dup->setControlInfo(lteInfo->dup());
                    switchPkt_dup->setOldConnection(true);
                    sendUpperPackets(switchPkt_dup);
                }
            }
            else if (lteInfo->getD2dTxPeerId() == peerId && (Direction)lteInfo->getDirection() == newDirection)
            {
                EV << NOW << " LteMacUeD2D::macHandleD2DModeSwitch - found new connection with cid " << cid << ", send signal to the RLC RX entity" << endl;
                if (oldDirection != newDirection)
                {
                    D2DModeSwitchNotification* switchPkt_dup = switchPkt->dup();
                    switchPkt_dup->setOldConnection(false);
                    switchPkt_dup->setControlInfo(lteInfo->dup());
                    sendUpperPackets(switchPkt_dup);
                }
            }
        }
    }
    delete uInfo;
    delete pkt;
}

void LteMacUeD2D::doHandover(MacNodeId targetEnb)
{
    EV<<"LteMacUeD2D::doHandover"<<endl;
    enbmac_ = check_and_cast<LteMacEnbD2D*>(getMacByMacNodeId(targetEnb));
    LteMacUe::doHandover(targetEnb);
}

void LteMacUeD2D::setSchedulingGrant(LteSidelinkGrant* grant)
{
    this->slGrant = grant;
}

LteSidelinkGrant* LteMacUeD2D::getSchedulingGrant(){
    return slGrant;
}

void LteMacUeD2D::finish()
{
    delete preconfiguredTxParams_;
}

