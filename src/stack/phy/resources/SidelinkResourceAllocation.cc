
#include "SidelinkResourceAllocation.h"
#include <math.h>
#include <assert.h>
#include <algorithm>
#include <iterator>
#include <vector>
#include <tuple>
#include "stack/phy/resources/SidelinkResourceAllocation.h"
#include "stack/phy/packet/LteFeedbackPkt.h"
#include "stack/d2dModeSelection/D2DModeSelectionBase.h"
#include "stack/phy/packet/SPSResourcePool.h"
#include "stack/phy/packet/cbr_m.h"
#include <unordered_map>
#include "common/LteControlInfo.h"
#include "stack/mac/configuration/SidelinkConfiguration.h"

Define_Module(SidelinkResourceAllocation);

SidelinkResourceAllocation::SidelinkResourceAllocation()
{
    handoverStarter_ = NULL;
    handoverTrigger_ = NULL;
    RBIndicesSCI.clear();
    RBIndicesData.clear();

}

SidelinkResourceAllocation::~SidelinkResourceAllocation()
{

}
void SidelinkResourceAllocation::handleMessage(cMessage* msg)
{
    if (msg->isSelfMessage())
    {
        EV<<"SidelinkResourceAllocation::handleMessage()"<<endl;
        handleSelfMessage(msg);

        //updateCBR();
    }
}
void SidelinkResourceAllocation::initialize(int stage)
{

    if (stage == inet::INITSTAGE_LOCAL)
    {
        EV<<"SidelinkResourceAllocation::initialize, stage: "<<stage<<endl;
        adjacencyPSCCHPSSCH_ = par("adjacencyPSCCHPSSCH");
        pStep_ = par("pStep");
        selectionWindowStartingSubframe_ = par("selectionWindowStartingSubframe");
        numSubchannels_ = par("numSubchannels");
        subchannelSize_ = par("subchannelSize");
        d2dDecodingTimer_ = NULL;
        transmitting_ = false;
        numberSubcarriersperPRB = par ("numberSubcarriersperPRB");
        numberSymbolsPerSlot = par("numberSymbolsPerSlot");
        bitsPerSymbolQPSK = par ("bitsPerSymbolQPSK");
        int thresholdRSSI = par("thresholdRSSI");
        subChRBStart_ = par ("subChRBStart");
        thresholdRSSI_ = (-112 + 2 * thresholdRSSI);
        numberPRBSCI = 2;
        d2dTxPower_ = par("d2dTxPower");
        if (d2dTxPower_ <= 0){
            d2dTxPower_ = txPower_;
        }
        nodeId_ = getAncestorPar("macNodeId");
        // The threshold has a size of 64, and allowable values of 0 - 66
        // Deciding on this for now as it makes the most sense (low priority for both then more likely to take it)
        // High priority for both then less likely to take it.
        for (int i = 1; i < 66; i++)
        {
            ThresPSSCHRSRPvector_.push_back(i);
        }

        numberSubchannels = registerSignal("numberSubchannels");
        totalCSR = registerSignal("totalCSR");
        syncLatency = registerSignal("syncLatency");
        resourceAllocationLatency = registerSignal("resourceAllocationLatency");
        configurationLatency = registerSignal("configurationLatency");
        halfDuplexError = registerSignal("halfDuplex");
        pcMode4 = registerSignal("packetCollisionMode4");
        sciReceived_ = 0;
        sciDecoded_ = 0;
        sciNotDecoded_ = 0;
        sciFailedHalfDuplex_ = 0;
        tbReceived_ = 0;
        tbDecoded_ = 0;
        tbFailedDueToNoSCI_ = 0;
        tbFailedButSCIReceived_ = 0;
        tbAndSCINotReceived_ = 0;
        tbFailedHalfDuplex_ = 0;
        subchannelReceived_ = 0;
        subchannelsUsed_ = 0;
        countHD=0;
        sensingWindowFront_ = 0; // Will ensure when we first update the sensing window we don't skip over the first element
        allocatedBlocksPrevious = 0;
        cResel =0;
        pcCountMode4 = 0;

    }
    else if (stage == inet::INITSTAGE_NETWORK_LAYER_2)
    {
        initialiseSensingWindow();
        sidelinkSynchronization();
    }

}

void SidelinkResourceAllocation::handleSelfMessage(cMessage *msg)
{


    if (msg->isName("d2dDecodingTimer"))
    {
        std::vector<int> missingTbs;
        for (int i=0; i<sciFrames_.size(); i++){
            bool foundTB=false;
            LteAirFrame* sciFrame = sciFrames_[i];
            UserControlInfo* sciInfo = check_and_cast<UserControlInfo*>(sciFrame->removeControlInfo());
            for (int j=0; j<tbFrames_.size();j++){
                LteAirFrame* tbFrame = tbFrames_[j];
                UserControlInfo* tbInfo = check_and_cast<UserControlInfo*>(tbFrame->removeControlInfo());
                if (sciInfo->getSourceId() == tbInfo->getSourceId()){
                    foundTB = true;
                    tbFrame->setControlInfo(tbInfo);
                    break;
                }
                tbFrame->setControlInfo(tbInfo);
            }
            if (!foundTB){
                missingTbs.push_back(i);
            }
            sciFrame->setControlInfo(sciInfo);
        }

        while (!sciFrames_.empty()){
            // Get received SCI and it's corresponding RsrpVector
            LteAirFrame* frame = sciFrames_.back();
            std::vector<double> rsrpVector = sciRsrpVectors_.back();
            std::vector<double> rssiVector = sciRssiVectors_.back();

            // Remove it from the vector
            sciFrames_.pop_back();
            sciRsrpVectors_.pop_back();
            sciRssiVectors_.pop_back();

            UserControlInfo* lteInfo = check_and_cast<UserControlInfo*>(frame->removeControlInfo());

            // decode the selected frame
            decodeAirFrame(frame, lteInfo);


            sciReceived_ = 0;
            sciDecoded_ = 0;
            sciNotDecoded_ = 0;
            sciFailedHalfDuplex_ = 0;
            subchannelReceived_ = 0;
            subchannelsUsed_ = 0;
        }
        int countTbs = 0;
        if (tbFrames_.empty()){
            for(countTbs=0; countTbs<missingTbs.size(); countTbs++){

            }
        }
        while (!tbFrames_.empty())
        {
            if(std::find(missingTbs.begin(), missingTbs.end(), countTbs) != missingTbs.end()) {
                // This corresponds to where we are missing a TB, record results as being negative to identify this.

            } else {
                LteAirFrame *frame = tbFrames_.back();
                std::vector<double> rsrpVector = tbRsrpVectors_.back();
                std::vector<double> rssiVector = tbRssiVectors_.back();

                tbFrames_.pop_back();
                tbRsrpVectors_.pop_back();
                tbRssiVectors_.pop_back();

                UserControlInfo *lteInfo = check_and_cast<UserControlInfo *>(frame->removeControlInfo());

                // decode the selected frame
                decodeAirFrame(frame, lteInfo);


                tbReceived_ = 0;
                tbDecoded_ = 0;
                tbFailedDueToNoSCI_ = 0;
                tbFailedButSCIReceived_ = 0;
                tbFailedHalfDuplex_ = 0;
            }
            countTbs++;
        }
        std::vector<cPacket*>::iterator it;
        for(it=scis_.begin();it!=scis_.end();it++)
        {
            delete(*it);
        }
        scis_.clear();
        delete msg;
        d2dDecodingTimer_ = NULL;
    }
    else if (msg->isName("updateSubframe"))
    {
        transmitting_ = false;
        //updateSubframe();
        // updateCBR();
        delete msg;
    }

    else if (msg->isName("SLSS"))
    {
        //Start sidelink synchronization
        EV<<"SLSS self"<<endl;
        sidelinkSynchronization();
    }
    else if (msg->isName("SIB21PreConfigured"))
    {

        // LtePhyUe::handleSelfMessage(msg);
        EV<<"SidelinkResourceAllocation::handleSelfMessage() SIB 21"<<endl;
        //initialiseSensingWindow();
        //updateSubframe();
        //updateCBR();
    }
    else
    {
        delete msg;
    }
}


void SidelinkResourceAllocation::handleUpperMessage(cMessage* msg)
{
    EV<<"SidelinkResourceAllocation::handleUpperMessage: "<<msg->getName()<<endl;
    UserControlInfo* lteInfo = check_and_cast<UserControlInfo*>(msg->removeControlInfo());

    if (msg->isName("LteMode4Grant") )
    {
        nodeType_ = UE;}
    else if ( msg->isName("LteMode3Grant"))
    {
        nodeType_ = ENODEB;
    }

    if (lteInfo->getFrameType() == SIDELINKGRANT)
    {
        // Generate CSRs or save the grant use when generating SCI information
        LteSidelinkGrant* grant = check_and_cast<LteSidelinkGrant*>(msg);
        /*            for (int i=0; i<numSubchannels_; i++)
            {
                // Mark all the subchannels as not sensed
                sensingWindow_[sensingWindowFront_][i]->setSensed(false);
            }*/

        EV<<"Number of previously granted blocks: "<<getAllocatedBlocksPrevious()<<"previous cResel: "<<getReselectionCounter()<<endl;

        //Mode 4
        if (nodeType_ ==UE)
        {

             if (getAllocatedBlocksPrevious() > 0 && getReselectionCounter()>0)
            {

                //Check if data size fits into previously allocated TB size
                int numberSymbolsPerPRB= numberSubcarriersperPRB*numberSymbolsPerSlot*bitsPerSymbolQPSK;
                int numberSymbolsTransmitBlock = grant->getTransmitBlockSize()/bitsPerSymbolQPSK;
                numberPRBTransmitBlock = (numberSymbolsTransmitBlock/numberSymbolsPerPRB)+1;
                int numberPRBNeeded =   numberPRBTransmitBlock+2; //SCI+TB
                if (numberPRBNeeded<=getAllocatedBlocksPrevious()-2) //" RBs for SCI
                {
                    //Use previous subchannels for the current subframes
                    RBIndicesData =  getPreviousSubchannelsData();
                    EV<<"Using previously allocated subchannels for data and SCI"<<  RBIndicesData.size()<<endl;
                    //determine the subframe
                    computeCSRs(grant,nodeType_);


                }
                if (numberPRBNeeded>getAllocatedBlocksPrevious()-2) //" RBs for SCI
                {
                    EV<<"Data size does not fit into previous allocation, need for re-allocation"<<endl;

                    //Reset counter and previous allocations
                    cResel=0;
                    setReselectionCounter(cResel);
                    setAllocatedBlocksPrevious(0);
                    computeCSRs(grant,nodeType_);
                    return;
                }

            }
             //This if loop should check for cResel - alloctaion for first time and re-allocation based on cResel
              if (getAllocatedBlocksPrevious() == 0 || getReselectionCounter()==0)
              {
                  // Generate a vector of CSRs and send it to the MAC layer
                  EV<<"Calling computeSCRs()"<<grant->getTransmitBlockSize()<<endl;
                  computeCSRs(grant,nodeType_);
                  //delete lteInfo;
                  //delete grant;
                  sciGrant_ = grant;
                  lteInfo->setUserTxParams(sciGrant_->getUserTxParams());
                  lteInfo->setGrantedBlocks(sciGrant_->getGrantedBlocks());
                  lteInfo->setDirection(D2D_MULTI);
                  return;
              }
        }

        //Mode 3
        if (nodeType_==ENODEB)
        {
            EV<<"Sidelink resource allocation according to mode 3"<<endl;
            computeCSRs(grant,nodeType_);
            return;
        }



    }

    else if (lteInfo->getFrameType() == HARQPKT)
    {
        LteAirFrame* frame = new LteAirFrame("harqFeedback-grant");
    }
    else
    {
        throw cRuntimeError("Invalid grant");
    }


}

LteAirFrame* SidelinkResourceAllocation::createSCIMessage(cMessage* msg, LteSidelinkGrant* grant)
{
    EV << NOW << " SidelinkResourceAllocation::createSCIMessage - Start creating SCI..." << endl;

    SidelinkControlInformation* sci = new SidelinkControlInformation("SCI Message");

    /*
     * Priority - takes values 0-7. It depends on the nature of the application. It is defined at the upper layers.

     */
    //
    sci->setPriority(grant->getSpsPriority());

    /* Resource reservation interval/Prsvp_TX
     *
     * 0 -> 16
     * 0 = not reserved
     * 1 = 100ms (1) RRI [Default]
     * 2 = 200ms (2) RRI
     * ...
     * 10 = 1000ms (10) RRI
     * 11 = 50ms (0.5) RRI
     * 12 = 20ms (0.2) RRI
     * 13 - 15 = Reserved
     *
     */
    if (grant->getExpiration() != 0)
    {
        sci->setResourceReservationInterval(0.1); //100 ms for cResel = [5,15]
    }
    else
    {
        sci->setResourceReservationInterval(0);
    }

    /* Frequency Resource Location for initial transmissiona nd re-transmission
     * Based on another parameter RIV
     * but size is
     * Log2(Nsubchannel(Nsubchannel+1)/2) (rounded up)
     * 0 - 8 bits
     * 0 - 256 different values
     *
     * Based on TS36.213 14.1.1.4C
     *     if SubchannelLength -1 < numSubchannels/2
     *         RIV = numSubchannels(SubchannelLength-1) + subchannelIndex
     *     else
     *         RIV = numSubchannels(numSubchannels-SubchannelLength+1) + (numSubchannels-1-subchannelIndex)
     */

    EV<<"numSubchannels_ : "<<numSubchannels_<<endl;
    EV<<"Lch: "<<grant->getNumSubchannels()<<endl; // SCI+TB size e.g. 9PRBs means two contiguous subchannels (write the logic )
    EV<<"starting subchannel: "<<grant->getStartingSubchannel()<<endl;

    unsigned  int riv;
    //
    if (grant->getNumSubchannels() -1 <= (numSubchannels_/2))
    {
        // RIV calculation for less than half+1
        riv = ((numSubchannels_ * (grant->getNumSubchannels() - 1)) + grant->getStartingSubchannel());
    }
    else
    {

        // RIV calculation for more than half size
        riv = ((numSubchannels_ * (numSubchannels_ - grant->getNumSubchannels() + 1)) + (numSubchannels_ - 1 - grant->getStartingSubchannel()));
    }

    sci->setFrequencyResourceLocation(riv);

    /* TimeGapRetrans
     * 1 - 15
     * ms from init to retrans
     */
    sci->setTimeGapRetrans(grant->getTimeGapTransRetrans());


    /* mcs
     * 5 bits
     * 26 combos
     * Technically the MAC layer determines the MCS that it wants the message sent with and as such it will be in the packet
     */
    sci->setMcs(grant->getMcs());

    /* retransmissionIndex
     * 0 / 1
     * if 0 retrans is in future/this is the first transmission
     * if 1 retrans is in the past/this is the retrans
     */
    if (grant->getRetransmission())
    {
        sci->setRetransmissionIndex(1);
    }
    else
    {
        sci->setRetransmissionIndex(0);
    }

    /* Filler up to 32 bits
     * Can just set the length to 32 bits and ignore the issue of adding filler
     */
    sci->setBitLength(32);

    //Print all SCI values
    EV<<"Priority: "<<grant->getSpsPriority()<<endl;
    EV<<"resource Reservation Interval: "<<(grant->getPeriod()/100)<<endl;
    EV<<"Frequency resource location of initial transmission and re-transmission (RIV): "<<riv<<endl;
    EV<<"Subframe gap: "<<grant->getTimeGapTransRetrans()<<endl;
    EV<<"Modulation and Coding Scheme: "<<grant->getMcs()<<endl;
    EV<<"Re-transmission index: "<<sci->getRetransmissionIndex()<<endl;
    UserControlInfo* lteInfo = new UserControlInfo();
    lteInfo->setGrantStartTime(grant->getStartTime());
    LteAirFrame* sciFrame = prepareAirFrame(sci, lteInfo);
    return sciFrame;

}

LteAirFrame* SidelinkResourceAllocation::prepareAirFrame(cMessage* msg, UserControlInfo* lteInfo){
    // Helper function to prepare airframe for sending.

    EV<<"SidelinkResourceAllocation::prepareAirFrame"<<nodeId_<<endl;
    LteAirFrame* frame = new LteAirFrame("SCIframe");
    frame->encapsulate(check_and_cast<cPacket*>(msg));
    frame->setSchedulingPriority(10); //Airframe priority = 10 as defined in LtePhyBase
    frame->setDuration(TTI);

    LtePhyBase* phy=check_and_cast<LtePhyBase*>(getParentModule()->getSubmodule("phy"));

    lteInfo->setSourceId(nodeId_);
    lteInfo->setCoord(phy->getCoord());
    lteInfo->setFrameType(SCIPKT);
    lteInfo->setDirection(D2D_MULTI);
    lteInfo->setTxPower(txPower_);
    lteInfo->setD2dTxPower(d2dTxPower_);
    frame->setControlInfo(lteInfo);
    return frame;
}


std::vector<int> SidelinkResourceAllocation::getallocationTBIndex(int bitLength, std::vector<int> subChSCI)
{
    allocatedPRBTBIndex.clear();

    int numberSymbolsPerPRB= numberSubcarriersperPRB*numberSymbolsPerSlot*bitsPerSymbolQPSK;
    int numberSymbolsTransmitBlock = bitLength/bitsPerSymbolQPSK;
    numberPRBTransmitBlock = (numberSymbolsTransmitBlock/numberSymbolsPerPRB)+1;

    //Allocate PRBs for TB contiguously after SCI

    int startSubChTB = subChSCI.at(1)+1;
    int beta = 2;
    EV<<"startSubChTB"<<subChSCI[0]<<" "<<subChSCI[1]<<endl;

    EV<<" numberPRBTransmitBlock: "<< numberPRBTransmitBlock<<endl;
    for (int j=0; j<numberPRBTransmitBlock; j++)
    {


        EV<<"TB indices: "<<startSubChTB+j<<endl;
        allocatedPRBTBIndex.push_back(startSubChTB+j);

        if (!adjacencyPSCCHPSSCH_)
        {
            allocatedPRBSciIndex.push_back(subChRBStart_ + numberPRBSCI*subchannelSize_+j+beta);
        }
    }
    return allocatedPRBTBIndex;

}

std::vector<int>  SidelinkResourceAllocation::getallocationSciIndex(int subChRBStart_)
{
    allocatedPRBSciIndex.clear();
    RbMap sciRbs;

    // Setup so SCI gets 2 RBs from the grantedBlocks.
    RbMap::iterator it;
    std::map<Band, unsigned int>::iterator jt;

    //for each Remote unit used to transmit the packet
    int allocatedBlocks = 0;



    //Allocate twp PRBS for SCI
    for (int j=0; j<2; j++)
    {
        EV<<"SCI indices: "<<subChRBStart_ + j<<endl;
        allocatedPRBSciIndex.push_back(subChRBStart_ + j);
    }

    return allocatedPRBSciIndex;
}

void SidelinkResourceAllocation::computeCSRs(LteSidelinkGrant* grant, LteNodeType nodeType_) {
    candidateSubframes.clear();

    if ((nodeType_==ENODEB) || (getAllocatedBlocksPrevious() == 0 && getReselectionCounter()==0 && nodeType_ == UE))
    {
        //Re-allocate subchannels and subframes
        RBIndicesSCI.clear();
        RBIndicesData.clear();
        resourceAllocationMap.clear();
        //Allocating subchannels
        int cResel = grant->getResourceReselectionCounter();
        setReselectionCounter(cResel);
        EV<<"Retrieve cResel: "<<getReselectionCounter()<<endl;
        subChRBStart_ = intuniform(0,std::ceil((numSubchannels_*subchannelSize_)/2)-1);

        EV<<"Start of subchannel: "<<subChRBStart_<<endl;

        RBIndicesSCI=getallocationSciIndex(subChRBStart_);
        RBIndicesData=getallocationTBIndex(grant->getTransmitBlockSize(),  RBIndicesSCI);

        grant->setStartingSubchannel(0);
    }




    EV<<"Allocating CSRs for : "<<nodeTypeToA(nodeType_)<<endl;


    int totalPRBsPerSubframe = 0;
    totalPRBsPerSubframe = RBIndicesSCI.size()+RBIndicesData.size();
    grant->setTotalGrantedBlocks(totalPRBsPerSubframe);
    EV<<"Total number of RBs for SCI+Data: "<<totalPRBsPerSubframe<<endl;

    binder_ = getBinder();
    std::map<MacNodeId,inet::Coord> broadcastUeMap = binder_->getBroadcastUeInfo();

    EV<<"broadcastUeMap: "<<broadcastUeMap.size()<<endl;

    std::map<MacNodeId,inet::Coord>::iterator itb = broadcastUeMap.begin();

    //Computing subframes
    int startSubFrame = intuniform(0,4);
    double maxLatency = grant->getMaximumLatency();
    int endSubFrame = startSubFrame+maxLatency;
    int selectionWindow =  maxLatency - startSubFrame;
    int possibleCSRSSelWindow;
    EV<<"Start subframe: "<<startSubFrame<<endl;
    EV<<"End subframe: "<<endSubFrame<<endl;

    //Discarding subframes where sync information appears - PSSS,SSSS,DMRS
    EV<<"Next SLSS: "<<nextSLSS<<endl;
    simtime_t selStartTime;
    simtime_t selEndTime;
    //Converting to ms
    if (nodeType_ == ENODEB)
    {
        selStartTime = (NOW+nextSLSS+TTI+startSubFrame/1000.0) .trunc(SIMTIME_MS);
        selEndTime =  (selStartTime+(maxLatency/1000.0)).trunc(SIMTIME_MS);

    }

    if (nodeType_==UE)
    {
        selStartTime = (nextSLSS+TTI+startSubFrame/1000.0) .trunc(SIMTIME_MS);
        selEndTime =  (selStartTime+(maxLatency/1000.0)).trunc(SIMTIME_MS);

    }

    tSync = (nextSLSS+0.001-NOW).dbl();  //it takes one TTI for SLSS acknowledgement
    EV<<"Synchronization latency: "<<tSync<<endl;
    emit(syncLatency,tSync);

    EV<<"selectionWindow start time:  "<<selStartTime<<endl;
    EV<<"selectionWindow end time:  "<<selEndTime<<endl;

    emit(configurationLatency,0.004);

    for (double k = selStartTime.dbl(); k<=selEndTime.dbl(); k=k+TTI)
    {
        candidateSubframes.push_back(k);

    }
    EV<<"Number of candidate subframes: "<< candidateSubframes.size()<<endl;
    int candidateSubframeInitial = 0;
    candidateSubframeInitial =candidateSubframes.size();


    unsigned int Prsvp_TX = grant->getPeriod(); //Resource reservation interval
    unsigned int  Prsvp_TX_prime = (Prsvp_TX*pStep_)/100;
    std::vector<double> possibleRRIs = grant->getPossibleRRIs();
    std::vector<double>::iterator k;

    if ((getAllocatedBlocksPrevious() == 0 || getReselectionCounter()==0) ||nodeType_ == ENODEB)
    {
        //Allocating subchannels
        int cResel = grant->getResourceReselectionCounter();
        setReselectionCounter(cResel);
        int randomIndexInitial = rand() % candidateSubframeInitial;
        simtime_t startFirstTransmissionInitial = candidateSubframes[randomIndexInitial];

        EV<<"First transmission initial: "<<startFirstTransmissionInitial<<endl;

        std::vector<std::pair<MacNodeId,double>> camueinfo = binder_->getCamUeinfo();
        std::vector<double> eraseSubframe ;
        double eraseSubframeTime;


        //Allocating subframes
        if(broadcastUeMap.size()>0)
        {
            for (; itb!=broadcastUeMap.end();++itb)
            {
                MacNodeId bid = itb->first;
                for (auto iter : camueinfo)
                {
                    if (bid == iter.first)
                    {
                        double y = iter.second;
                        for(int j=0; j<cResel-1;j++)
                        {
                            eraseSubframeTime = (y+j*Prsvp_TX_prime);
                            if (eraseSubframeTime >= selStartTime.dbl() && eraseSubframeTime <=selEndTime.dbl())
                            {
                                EV<<"erase subframe: "<<(y+j*Prsvp_TX)<<endl;

                                if ((y+j*Prsvp_TX)==startFirstTransmissionInitial.dbl())
                                {
                                    countHD=countHD+1;
                                    emit(halfDuplexError,countHD);
                                }
                                eraseSubframe.push_back((y+j*Prsvp_TX));
                            }
                        }


                    }
                }
            }
        }


        //Find the subframes to be discarded
        for (auto iter : eraseSubframe)
        {
            EV<<"iter: "<<iter<<endl;
            std::vector<double>::iterator it = std::find(candidateSubframes.begin(), candidateSubframes.end(), iter);
            int index = std::distance(candidateSubframes.begin(), it);
            EV<<"Erase index: "<<index<<endl;


            if(it!=candidateSubframes.end())
            {
                candidateSubframes.erase(it);
            }
            else
            {
                candidateSubframes.pop_back();
            }
        }

        int randomIndex = rand() % candidateSubframes.size();
        simtime_t startFirstTransmission = candidateSubframes[randomIndex];

        //Print all candidate subframes

        for (int k=0;k<candidateSubframes.size();k++)
        {
            resourceAllocationMap.push_back(std::make_tuple(candidateSubframes[k],RBIndicesSCI,RBIndicesData));
        }

        //Detecting packet collisions
        sort(eraseSubframe.begin(), eraseSubframe.end());

        for(int k =0; k<eraseSubframe.size();k++)
        {

            if (eraseSubframe[k]==eraseSubframe[k+1])
            {
                pcCountMode4 = pcCountMode4+1;
                emit(pcMode4,pcCountMode4);
                EV<<"Duplicates: "<< eraseSubframe[k] << " and "<<eraseSubframe[k+1]<<endl;
            }

        }

        grant->setTotalGrantedBlocks(RBIndicesSCI.size()+RBIndicesData.size());
        setPreviousSubchannelsData(RBIndicesData);
        EV<<"Set total granted blocks: "<<grant->getTotalGrantedBlocks()<<endl;
        EV<<"First transmission: "<<startFirstTransmission<<endl;
        grant->setStartTime(startFirstTransmission);
        FirstTransmission = startFirstTransmission.dbl();
        setFirstTransmissionPrevious(FirstTransmission);
        binder_->updatePeriodicCamTransmissions(nodeId_,startFirstTransmission.dbl());

        EV<<"Resource allocation latency: "<<(startFirstTransmission-selStartTime).dbl()<<endl;
        emit(resourceAllocationLatency,(startFirstTransmission-selStartTime).dbl());

        //throw cRuntimeError("computeCSRs");
        EV<<"Erase subframe size: "<< eraseSubframe.size()<<endl;
        EV<<"candidateSubframes size initial: "<<candidateSubframeInitial<<endl;
        EV<<"candidateSubframes size limit: "<<0.8*candidateSubframeInitial<<endl;
        if(eraseSubframe.size()>(0.8*candidateSubframeInitial))
        {
            //RSRP

            EV<<"Filtering of erased subframes needed: "<<endl;
            //RSSI
            for (int k=0; k<eraseSubframe.size();k++)
            {
                optimalCSRs=selectBestRSSIs(eraseSubframe, grant,eraseSubframe[k]);
            }
        }
        else
        {
            for (int k=0; k<candidateSubframes.size();k++)
            {
                optimalCSRs.emplace_back(0,9,candidateSubframes[k]);
            }
        }
    }

    if (getAllocatedBlocksPrevious() > 0 && getReselectionCounter()>0 && nodeType_==UE) //only for mode 4
    {
        FirstTransmission = getFirstTransmissionPrevious()+0.1;//increment by RRI for subsequent packet transmissions
        setFirstTransmissionPrevious(FirstTransmission);
        EV<<"First transmission subsequent: "<< FirstTransmission<<endl;
        binder_->updatePeriodicCamTransmissions(nodeId_, FirstTransmission);
        grant->setStartTime( FirstTransmission);


    }

    // Send the packet up to the MAC layer where it will choose the CSR and the retransmission if that is specified
    // Need to generate the message that is to be sent to the upper layers.
    SPSResourcePool* candidateResourcesMessage = new SPSResourcePool("CSRs");
    candidateResourcesMessage->setCSRs(optimalCSRs);
    LtePhyBase* phy=check_and_cast<LtePhyBase*>(getParentModule()->getSubmodule("phy"));
    phy->sendUpperPackets(candidateResourcesMessage);

}

std::vector<std::tuple<double, int, double>> SidelinkResourceAllocation::selectBestRSSIs(std::vector<double> subframes, LteSidelinkGrant* &grant, double subFrame)
{
    subch = new Subchannel(numSubchannels_,subFrame);
    EV << NOW << " LtePhyVUeMode4::selectBestRSSIs - Selecting best CSRs from possible CSRs..." << endl;
    int decrease = pStep_;
    if (grant->getPeriod() < 100)
    {
        // Same as pPrimeRsvpTx from other parts of the function
        decrease = (pStep_ * grant->getPeriod())/100;
    }

    int maxLatency = grant->getMaximumLatency();

    // Start and end of Selection Window.
    int minSelectionIndex = (10 * pStep_) + selectionWindowStartingSubframe_;
    int maxSelectionIndex = (10 * pStep_) + maxLatency;

    unsigned int grantLength = grant->getNumSubchannels();

    // This will be avgRSSI -> (subframeIndex, subchannelIndex)
    std::vector<std::tuple<double, int, double>> orderedCSRs;

    LtePhyBase* phy=check_and_cast<LtePhyBase*>(getParentModule()->getSubmodule("phy"));
    std::vector<std::vector<std::pair<Band,double>>> rssiD2DPeers=phy->getRSSIVector();

    EV<<"RSSI vector size: "<<rssiD2DPeers.size()<<endl;
    double averageRSSI = 0.0;
    for(int k=0; k<rssiD2DPeers.size();k++)
    {
        averageRSSI=averageRSSI+subch->getAverageRSSI(rssiD2DPeers[k]);

    }

    double averageRSSIPeers =averageRSSI/rssiD2DPeers.size();

    orderedCSRs.emplace_back(averageRSSIPeers, 9, subFrame);
    // Shuffle ensures that the subframes and subchannels appear in a random order, making the selections more balanced
    // throughout the selection window.
    std::random_shuffle (orderedCSRs.begin(), orderedCSRs.end());

    /* std::sort(begin(orderedCSRs), end(orderedCSRs), [](const std::tuple<double, int, int> &t1, const std::tuple<double, int, int> &t2) {
            return get<0>(t1) < get<0>(t2); // or use a custom compare function
        });*/

    int minSize = std::round(totalPossibleCSRs * .2);
    orderedCSRs.resize(minSize);

    return orderedCSRs;
}

void SidelinkResourceAllocation::storeAirFrame(LteAirFrame* frame, UserControlInfo* lteInfo)
{
    // implements the capture effect
    // store the frame received from the nearest transmitter

    EV<<""<<endl;
    // Need to be able to figure out which subchannel is associated to the Rbs in this case
    if (lteInfo->getFrameType() == SCIPKT){
        sciFrames_.push_back(frame);
    }
    else{
        tbFrames_.push_back(frame);
    }

    decodeAirFrame(frame,lteInfo);
}

void SidelinkResourceAllocation::decodeAirFrame(LteAirFrame* frame, UserControlInfo* lteInfo)
{
    EV << NOW << " SidelinkResourceAllocation::decodeAirFrame - Start decoding..." << endl;


}

std::tuple<int,int> SidelinkResourceAllocation::decodeRivValue(SidelinkControlInformation* sci, UserControlInfo* sciInfo)
{
    EV << NOW << " SidelinkResourceAllocation::decodeRivValue - Decoding RIV value of SCI allows correct placement in sensing window..." << endl;
    int subchannelIndex = 0;
    int lengthInSubchannels = numSubchannels_;
    return std::make_tuple(subchannelIndex, lengthInSubchannels);
}

void  SidelinkResourceAllocation::initialiseSensingWindow()
{
    Enter_Method("initialiseSensingWindow()");
    EV << NOW << " SidelinkResourceAllocation::initialiseSensingWindow - creating subframes to be added to sensingWindow..." << endl;

    simtime_t subframeTime = NOW - TTI;

    //EV<<"subframeTime: "<<subframeTime<<endl;
    // Reserve the full size of the sensing window (might improve efficiency).
    sensingWindow_.reserve(10*pStep_);

    EV<<"Reserve: "<<10*pStep_<< "sensing window size: "<<sensingWindow_.size()<<endl;
    Band band = 0;

    while(sensingWindow_.size() < 10*pStep_)
    {
        subframe.reserve(numSubchannels_);

        if (!adjacencyPSCCHPSSCH_)
        {
            // This assumes the bands only every have 1 Rb (which is fine as that appears to be the case)
            band = numSubchannels_*2;
        }
        for (int i = 0; i < numSubchannels_; i++) {
            Subchannel *currentSubchannel = new Subchannel(subchannelSize_, subframeTime);
            // Need to determine the RSRP and RSSI that corresponds to background noise
            // Best off implementing this in the channel model as a method.

            std::vector <Band> occupiedBands;

            int overallCapacity = 0;

            // Ensure the subchannel is allocated the correct number of RBs
            while (overallCapacity < subchannelSize_ && band < getBinder()->getNumBands()) {

                // This acts like there are multiple RBs per band which is not allowed.
                occupiedBands.push_back(band);
                ++overallCapacity;
                ++band;

            }

            currentSubchannel->setOccupiedBands(occupiedBands);
            subframe.push_back(currentSubchannel);
        }
        sensingWindow_.push_back(subframe);
        subframeTime += TTI;
    }

    EV<<"Number of resource elements inside sensing window: "<<subframe.size()<<" "<<"Sensing window size: "<<sensingWindow_.size()<<endl;
    EV<<"Number of subchannels: "<<numSubchannels_<<endl;

}

simtime_t SidelinkResourceAllocation::sidelinkSynchronization()
{
    Enter_Method("sidelinkSynchronization()");
    //Synchronization messages are scheduled every 160ms
    EV<<"Synchronization subframes"<<endl;
    slsync = new  cMessage("SLSS");

    SidelinkSynchronization* slss = new SidelinkSynchronization("SLSS");
    LteAirFrame* frame = new LteAirFrame("SLSS");
    UserControlInfo* lteInfo = new UserControlInfo ();
    frame->encapsulate(check_and_cast<cPacket*>(slss));
    lteInfo->setFrameType(SYNC);
    lteInfo->setDirection(D2D_MULTI);
    frame->setControlInfo(lteInfo);
    slsync->setSchedulingPriority(0);

    nextSLSS = (NOW+160*TTI);
    scheduleAt(NOW+160*TTI, slsync);

    LtePhyBase* phy=check_and_cast<LtePhyBase*>(getParentModule()->getSubmodule("phy"));
    phy->sendBroadcast(frame);
    return nextSLSS;
}


void SidelinkResourceAllocation::finish()
{

    /*    std::vector<std::vector<Subchannel *>>::iterator it;
    for (it=sensingWindow_.begin();it!=sensingWindow_.end();it++)
    {
        std::vector<Subchannel *>::iterator jt;
        for (jt=it->begin();jt!=it->end();jt++)
        {
            delete (*jt);
        }
    }
    sensingWindow_.clear();*/


}



