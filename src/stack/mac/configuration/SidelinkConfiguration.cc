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

#include "SidelinkConfiguration.h"

#include "stack/mac/buffer/harq/LteHarqBufferRx.h"
#include "stack/mac/buffer/LteMacQueue.h"
#include "stack/mac/buffer/harq_d2d/LteHarqBufferRxD2D.h"

#include "stack/mac/scheduler/LteSchedulerUeUl.h"
#include "stack/phy/packet/SPSResourcePool.h"
#include "stack/phy/packet/cbr_m.h"
#include "stack/phy/resources/Subchannel.h"
#include "stack/mac/amc/AmcPilotD2D.h"
#include "common/LteCommon.h"
#include "stack/phy/layer/LtePhyBase.h"
#include "inet/networklayer/common/InterfaceEntry.h"
#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/ipv4/IPv4InterfaceData.h"
#include "stack/mac/amc/LteMcs.h"
#include <map>
#include "stack/mac/packet/SPSResourcePoolMode4.h"
Define_Module(SidelinkConfiguration);

SidelinkConfiguration::SidelinkConfiguration()
{
    mac = NULL;
    mode4Grant = NULL;
    mode3Grant = NULL;
    schedulingGrant_ = NULL;
    slGrant = NULL;
}

SidelinkConfiguration::~SidelinkConfiguration()
{
    delete mac;

}

void SidelinkConfiguration::initialize(int stage)
{

    if (stage !=inet::INITSTAGE_NETWORK_LAYER_3)
        //  LteMacUeD2D::initialize(stage);
    {}

    if (stage == inet::INITSTAGE_LOCAL)
    {
        EV<<"SidelinkConfiguration::initialize, stage: "<<stage<<endl;
        parseUeTxConfig(par("txConfig").xmlValue());
        parseCbrTxConfig(par("txConfig").xmlValue());
        parseRriConfig(par("txConfig").xmlValue());
        restrictResourceReservationPeriod = validResourceReservationIntervals_.at(0);
        resourceReselectionCounter_ = par("resourceReselectionCounter");
        subchannelSize_ = par("subchannelSize");
        numSubchannels_ = par("numSubchannels");
        probResourceKeep_ = par("probResourceKeep");
        usePreconfiguredTxParams_ = par("usePreconfiguredTxParams");
        reselectAfter_ = par("reselectAfter");
        useCBR_ = par("useCBR");
        packetDropping_ = par("packetDropping");
        maximumCapacity_ = 0;
        cbr_=0;
        currentCw_=0;
        missedTransmissions_=0;
        expiredGrant_ = false;

        // Register the necessary signals for this simulation
        grantStartTime          = registerSignal("grantStartTime");
        grantBreak              = registerSignal("grantBreak");
        grantBreakTiming        = registerSignal("grantBreakTiming");
        grantBreakSize          = registerSignal("grantBreakSize");
        droppedTimeout          = registerSignal("droppedTimeout");
        grantBreakMissedTrans   = registerSignal("grantBreakMissedTrans");
        missedTransmission      = registerSignal("missedTransmission");
        selectedMCS             = registerSignal("selectedMCS");
        selectedSubchannelIndex = registerSignal("selectedSubchannelIndex");
        selectedNumSubchannels  = registerSignal("selectedNumSubchannels");
        maximumCapacity         = registerSignal("maximumCapacity");
        grantRequest            = registerSignal("grantRequest");
        packetDropDCC           = registerSignal("packetDropDCC");
        macNodeID               = registerSignal("macNodeID");
        dataSize                = registerSignal("dataPDUSizeTransmitted");

    }
    else if (stage == inet::INITSTAGE_NETWORK_LAYER_3)
    {
        deployer_ = getCellInfo(nodeId_);
        numAntennas_ = getNumAntennas();
        mcsScaleD2D_ = deployer_->getMcsScaleUl();
        d2dMcsTable_.rescale(mcsScaleD2D_);

        if (usePreconfiguredTxParams_)
        {
            preconfiguredTxParams_ = getPreconfiguredTxParams();
        }

        // LTE UE Section
        nodeId_ = getAncestorPar("macNodeId");

        //emit(macNodeID, nodeId_);

        /* Insert UeInfo in the Binder */
        ueInfo_ = new UeInfo();
        ueInfo_->id = nodeId_;            // local mac ID
        ueInfo_->cellId = cellId_;        // cell ID
        ueInfo_->init = false;            // flag for phy initialization
        ueInfo_->ue = this->getParentModule()->getParentModule();  // reference to the UE module

        // Get the Physical Channel reference of the node
        ueInfo_->phy = check_and_cast<LtePhyBase*>(ueInfo_->ue->getSubmodule("lteNic")->getSubmodule("phy"));

        // binder_->addUeInfo(ueInfo_);
    }
}

void SidelinkConfiguration::parseUeTxConfig(cXMLElement* xmlConfig)
{
    if (xmlConfig == 0)
        throw cRuntimeError("No sidelink configuration file specified");

    // Get channel Model field which contains parameters fields
    cXMLElementList ueTxConfig = xmlConfig->getElementsByTagName("userEquipment-txParameters");

    if (ueTxConfig.empty())
        throw cRuntimeError("No userEquipment-txParameters configuration found in configuration file");

    if (ueTxConfig.size() > 1)
        throw cRuntimeError("More than one userEquipment-txParameters configuration found in configuration file.");

    cXMLElement* ueTxConfigData = ueTxConfig.front();

    ParameterMap params;
    getParametersFromXML(ueTxConfigData, params);

    //get lambda max threshold
    ParameterMap::iterator it = params.find("minMCS-PSSCH");
    if (it != params.end())
    {
        EV<<"Parsing minMCS-PSSCH SidelinkConfiguration::parseUeTxConfig"<<endl;
        minMCSPSSCH_ = (int)it->second;
    }
    else
        minMCSPSSCH_ = (int)par("minMCSPSSCH");
    it = params.find("maxMCS-PSSCH");
    if (it != params.end())
    {
        maxMCSPSSCH_ = (int)it->second;
    }
    else
        maxMCSPSSCH_ = (int)par("minMCSPSSCH");
    it = params.find("minSubchannel-NumberPSSCH");
    if (it != params.end())
    {
        minSubchannelNumberPSSCH_ = (int)it->second;
    }
    else
        minSubchannelNumberPSSCH_ = (int)par("minSubchannelNumberPSSCH");
    it = params.find("maxSubchannel-NumberPSSCH");
    if (it != params.end())
    {
        maxSubchannelNumberPSSCH_ = (int)it->second;
    }
    else
        maxSubchannelNumberPSSCH_ = (int)par("maxSubchannelNumberPSSCH");
    it = params.find("allowedRetxNumberPSSCH");
    if (it != params.end())
    {
        allowedRetxNumberPSSCH_ = (int)it->second;
    }
    else
        allowedRetxNumberPSSCH_ = (int)par("allowedRetxNumberPSSCH");
}

void SidelinkConfiguration::parseCbrTxConfig(cXMLElement* xmlConfig)
{

    if (xmlConfig == 0)
        throw cRuntimeError("No cbr configuration specified");

    // Get channel Model field which contains parameters fields
    cXMLElementList cbrTxConfig = xmlConfig->getElementsByTagName("Sl-CBR-CommonTxConfigList");

    if (cbrTxConfig.empty())
        throw cRuntimeError("No Sl-CBR-CommonTxConfigList found in configuration file");

    cXMLElement* cbrTxConfigData = cbrTxConfig.front();

    ParameterMap params;
    getParametersFromXML(cbrTxConfigData, params);

    //get lambda max threshold
    ParameterMap::iterator it = params.find("default-cbr-ConfigIndex");
    if (it != params.end())
    {
        defaultCbrIndex_ = it->second;
        currentCbrIndex_ = defaultCbrIndex_;
    }

    cXMLElementList cbrLevelConfigs = xmlConfig->getElementsByTagName("cbr-ConfigIndex");

    if (cbrLevelConfigs.empty())
        throw cRuntimeError("No cbr-Levels-Config found in configuration file");

    cXMLElementList::iterator xmlIt;
    for(xmlIt = cbrLevelConfigs.begin(); xmlIt != cbrLevelConfigs.end(); xmlIt++)
    {
        std::unordered_map<std::string, double> cbrLevelsMap;
        ParameterMap cbrLevelsParams;
        getParametersFromXML((*xmlIt), cbrLevelsParams);
        it = cbrLevelsParams.find("cbr-lower");
        if (it != cbrLevelsParams.end())
        {
            cbrLevelsMap.insert(std::pair<std::string, double>("cbr-lower",  it->second));
        }
        it = cbrLevelsParams.find("cbr-upper");
        if (it != cbrLevelsParams.end())
        {
            cbrLevelsMap.insert(std::pair<std::string, double>("cbr-upper",  it->second));
        }
        it = cbrLevelsParams.find("cbr-PSSCH-TxConfig-Index");
        if (it != cbrLevelsParams.end())
        {
            cbrLevelsMap.insert(std::pair<std::string, double>("cbr-PSSCH-TxConfig-Index",  it->second));
        }
        cbrLevels_.push_back(cbrLevelsMap);
    }

    cXMLElementList cbrTxConfigs = xmlConfig->getElementsByTagName("cbr-PSSCH-TxConfig");

    if (cbrTxConfigs.empty())
        throw cRuntimeError("No CBR-TxConfig found in configuration file");

    cXMLElementList cbrTxParams = xmlConfig->getElementsByTagName("txParameters");

    for(xmlIt = cbrTxParams.begin(); xmlIt != cbrTxParams.end(); xmlIt++)
    {
        std::unordered_map<std::string, double> cbrMap;
        ParameterMap cbrParams;
        getParametersFromXML((*xmlIt), cbrParams);
        it = cbrParams.find("minMCS-PSSCH");
        if (it != cbrParams.end())
        {
            cbrMap.insert({"minMCS-PSSCH",  it->second});
        }
        else
            cbrMap.insert({"minMCS-PSSCH",  par("minMCSPSSCH")});
        it = cbrParams.find("maxMCS-PSSCH");
        if (it != cbrParams.end())
        {
            cbrMap.insert({"maxMCS-PSSCH",  it->second});
        }
        else
            cbrMap.insert({"maxMCS-PSSCH",  par("maxMCSPSSCH")});
        it = cbrParams.find("minSubchannel-NumberPSSCH");
        if (it != cbrParams.end())
        {
            cbrMap.insert({"minSubchannel-NumberPSSCH",  it->second});
        }
        else
            cbrMap.insert({"minSubchannel-NumberPSSCH",  par("minSubchannelNumberPSSCH")});
        it = cbrParams.find("maxSubchannel-NumberPSSCH");
        if (it != cbrParams.end())
        {
            cbrMap.insert({"maxSubchannel-NumberPSSCH",  it->second});
        }
        else
            cbrMap.insert({"maxSubchannel-NumberPSSCH",  par("maxSubchannelNumberPSSCH")});
        it = cbrParams.find("allowedRetxNumberPSSCH");
        if (it != cbrParams.end())
        {
            cbrMap.insert({"allowedRetxNumberPSSCH",  it->second});
        }
        else
            cbrMap.insert({"allowedRetxNumberPSSCH",  par("allowedRetxNumberPSSCH")});
        it = cbrParams.find("cr-Limit");
        if (it != cbrParams.end())
        {
            cbrMap.insert({"cr-Limit",  it->second});
        }

        cbrPSSCHTxConfigList_.push_back(cbrMap);
        EV<<"Parsing CBR"<<cbrPSSCHTxConfigList_.size()<<endl;
    }
}

void SidelinkConfiguration::parseRriConfig(cXMLElement* xmlConfig)
{
    if (xmlConfig == 0)
        throw cRuntimeError("No cbr configuration specified");

    // Get channel Model field which contains parameters fields
    cXMLElementList rriConfig = xmlConfig->getElementsByTagName("RestrictResourceReservationPeriodList");

    if (rriConfig.empty())
        throw cRuntimeError("No RestrictResourceReservationPeriodList found in configuration file");

    cXMLElementList rriConfigs = xmlConfig->getElementsByTagName("RestrictResourceReservationPeriod");

    if (rriConfigs.empty())
        throw cRuntimeError("No RestrictResourceReservationPeriods found in configuration file");

    cXMLElementList::iterator xmlIt;
    for(xmlIt = rriConfigs.begin(); xmlIt != rriConfigs.end(); xmlIt++)
    {
        ParameterMap rriParams;
        getParametersFromXML((*xmlIt), rriParams);
        ParameterMap::iterator it = rriParams.find("rri");
        if (it != rriParams.end())
        {
            validResourceReservationIntervals_.push_back(it->second);
        }
    }
}

int SidelinkConfiguration::getNumAntennas()
{
    /* Get number of antennas: +1 is for MACRO */
    return deployer_->getNumRus() + 1;
}

void SidelinkConfiguration::macPduMake()
{

}

UserTxParams* SidelinkConfiguration::getPreconfiguredTxParams()
{
    UserTxParams* txParams = new UserTxParams();

    // default parameters for D2D
    txParams->isSet() = true;
    txParams->writeTxMode(SINGLE_ANTENNA_PORT0);
    Rank ri = 1;                                              // rank for TxD is one
    txParams->writeRank(ri);
    txParams->writePmi(intuniform(1, pow(ri, (double) 2)));   // taken from LteFeedbackComputationRealistic::computeFeedback

    BandSet b;
    for (Band i = 0; i < deployer_->getNumBands(); ++i) b.insert(i);
    txParams->writeBands(b);

    RemoteSet antennas;
    antennas.insert(MACRO);
    txParams->writeAntennas(antennas);

    return txParams;
}

void SidelinkConfiguration::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage())
    {
        //LteMacUeD2D::handleMessage(msg);
        return;
    }


    cPacket* pkt = check_and_cast<cPacket *>(msg);
    cGate* incoming = pkt->getArrivalGate();


    if (strcmp(pkt->getName(), "CBR") == 0)
    {
        EV<<"REceived CBR message from gate: "<<incoming<<endl;

        Cbr* cbrPkt = check_and_cast<Cbr*>(pkt);
        cbr_ = cbrPkt->getCbr();

        currentCbrIndex_ = defaultCbrIndex_;
        if (useCBR_)
        {
            std::vector<std::unordered_map<std::string, double>>::iterator it;
            for (it = cbrLevels_.begin(); it!=cbrLevels_.end(); it++)
            {
                double cbrUpper = (*it).at("cbr-upper");
                double cbrLower = (*it).at("cbr-lower");
                double index = (*it).at("cbr-PSSCH-TxConfig-Index");
                if (cbrLower == 0){
                    if (cbr_< cbrUpper)
                    {
                        currentCbrIndex_ = (int)index;
                        break;
                    }
                } else if (cbrUpper == 1){
                    if (cbr_ > cbrLower)
                    {
                        currentCbrIndex_ = (int)index;
                        break;
                    }
                } else {
                    if (cbr_ > cbrLower && cbr_<= cbrUpper)
                    {
                        currentCbrIndex_ = (int)index;
                        break;
                    }
                }
            }
        }

        int b;
        int a;
        int subchannelsUsed = 0;
        // CR limit calculation
        // determine b
        if (schedulingGrant_ != NULL){
            if (expirationCounter_ > 499){
                b = 499;
            } else {
                b = expirationCounter_;
            }
            subchannelsUsed += b / schedulingGrant_->getPeriod();
        } else {
            b = 0;
        }
        // determine a
        a = 999 - b;

        // determine previous transmissions -> Need to account for if we have already done a drop. Must maintain a
        // history of past transmissions i.e. subchannels used and subframe in which they occur. delete entries older
        // than 1000.

        std::unordered_map<double, int>::const_iterator it = previousTransmissions_.begin();
        while (it != previousTransmissions_.end()){
            if (it->first < NOW.dbl() - 1){
                it = previousTransmissions_.erase(it);
            } else if (it->first > NOW.dbl() - (0.1 * a)) {
                subchannelsUsed += it->second;
                it++;
            }
        }

        // calculate cr
        channelOccupancyRatio_ = subchannelsUsed /(numSubchannels_ * 1000.0);
        EV<<"channelOccupancyRatio_: "<<channelOccupancyRatio_<<endl;
        // message from PHY_to_MAC gate (from lower layer)
        //emit(receivedPacketFromLowerLayer, pkt);
        throw cRuntimeError("SLConfig CBR");
        LteMacBase* mac = dynamic_cast<LteMacBase*>(getParentModule()->getSubmodule("mac"));
        mac->sendUpperPackets(cbrPkt);

        return;
    }

    if (msg->isName("newDataPkt"))
    {
        LteMacBase* mac = dynamic_cast<LteMacBase*>(getParentModule()->getSubmodule("mac"));

        if (mac->getIpBased()==false)
        {
            FlowControlInfoNonIp* lteInfo = check_and_cast<FlowControlInfoNonIp*>(pkt->removeControlInfo());
            lteInfo->setIpBased(false);

            receivedTime_ = NOW;
            simtime_t elapsedTime = receivedTime_ - lteInfo->getCreationTime();
            simtime_t duration = SimTime(lteInfo->getDuration(), SIMTIME_MS);
            duration = duration - elapsedTime;
            double dur = duration.dbl();
            remainingTime_ = lteInfo->getDuration() - dur;

            if (schedulingGrant_ != NULL && periodCounter_ > remainingTime_)
            {
                //emit(grantBreakTiming, 1);
                //delete schedulingGrant_;
                //schedulingGrant_ = NULL;
                mode4Grant=   macGenerateSchedulingGrant(remainingTime_, lteInfo->getPriority(), pkt->getBitLength());
            }
            else if (schedulingGrant_ == NULL)
            {
                mode4Grant= macGenerateSchedulingGrant(remainingTime_, lteInfo->getPriority(), pkt->getBitLength());

            }
            else
            {
                LteSidelinkGrant* mode4Grant = check_and_cast<LteSidelinkGrant*>(schedulingGrant_);
                mode4Grant->setSpsPriority(lteInfo->getPriority());
                // Need to get the creation time for this
                mode4Grant->setMaximumLatency(remainingTime_);
            }
            // Need to set the size of our grant to the correct size we need to ask rlc for, i.e. for the sdu size.
            mode4Grant->setGrantedCwBytes((MAX_CODEWORDS - currentCw_), pkt->getBitLength());
            mode4Grant->setPacketId(mac->getPacketId());
            mode4Grant->setCamId(mac->getCAMId());
            EV<<"Mode4Grant CAM Id: "<<mac->getCAMId()<<endl;
            slGrant = mode4Grant;
            setSidelinkGrant(slGrant);
            pkt->setControlInfo(lteInfo);
        }




        if (mac->getIpBased()==true)
        {
            FlowControlInfo*  lteInfo = check_and_cast<FlowControlInfo*>(pkt->removeControlInfo());
            lteInfo->setIpBased(true);

            receivedTime_ = NOW;
            simtime_t elapsedTime = receivedTime_ - lteInfo->getCreationTime();
            simtime_t duration = SimTime(lteInfo->getDuration(), SIMTIME_MS);
            duration = duration - elapsedTime;
            double dur = duration.dbl();
            remainingTime_ = lteInfo->getDuration() - dur;

            if (schedulingGrant_ != NULL && periodCounter_ > remainingTime_)
            {
                //emit(grantBreakTiming, 1);
                //delete schedulingGrant_;
                //schedulingGrant_ = NULL;
                mode4Grant=   macGenerateSchedulingGrant(remainingTime_, lteInfo->getPriority(), pkt->getBitLength());
            }
            else if (schedulingGrant_ == NULL)
            {
                mode4Grant= macGenerateSchedulingGrant(remainingTime_, lteInfo->getPriority(), pkt->getBitLength());

            }
            else
            {
                LteSidelinkGrant* mode4Grant = check_and_cast<LteSidelinkGrant*>(schedulingGrant_);
                mode4Grant->setSpsPriority(lteInfo->getPriority());
                // Need to get the creation time for this
                mode4Grant->setMaximumLatency(remainingTime_);
            }
            // Need to set the size of our grant to the correct size we need to ask rlc for, i.e. for the sdu size.
            mode4Grant->setGrantedCwBytes((MAX_CODEWORDS - currentCw_), pkt->getBitLength());
            mode4Grant->setPacketId(mac->getPacketId());
            EV<<"Grant for packetId: "<<mode4Grant->getPacketId()<<endl;
            slGrant = mode4Grant;
            setSidelinkGrant(slGrant);
            pkt->setControlInfo(lteInfo);
        }
    }


}


void SidelinkConfiguration::assignGrantToData(DataArrival* pkt, std::string rrcState)
{
    rrcCurrentState = rrcState;
    LteMacBase* mac = dynamic_cast<LteMacBase*>(getParentModule()->getSubmodule("mac"));
    /*


    if(rrcState=="RRC_IDLE")
    {

        FlowControlInfoNonIp* lteInfo = check_and_cast<FlowControlInfoNonIp*>(pkt->removeControlInfo());
        receivedTime_ = NOW;
        EV<<"RRC State: "<<rrcState<<endl;

        simtime_t elapsedTime = receivedTime_ - lteInfo->getCreationTime();
        simtime_t duration = SimTime(lteInfo->getDuration(), SIMTIME_MS);
        duration = duration - elapsedTime;
        double dur = duration.dbl();
        remainingTime_ = lteInfo->getDuration() - dur;

        if (schedulingGrant_ != NULL && periodCounter_ > remainingTime_)
        {
            emit(grantBreakTiming, 1);
            //delete schedulingGrant_;
            //schedulingGrant_ = NULL;
            mode4Grant=   macGenerateSchedulingGrant(remainingTime_, lteInfo->getPriority(), pkt->getBitLength());
        }
        else if (schedulingGrant_ == NULL)
        {
            mode4Grant= macGenerateSchedulingGrant(remainingTime_, lteInfo->getPriority(), pkt->getBitLength());

        }
        else
        {
            LteSidelinkGrant* mode4Grant = check_and_cast<LteSidelinkGrant*>(schedulingGrant_);
            mode4Grant->setSpsPriority(lteInfo->getPriority());
            // Need to get the creation time for this
            mode4Grant->setMaximumLatency(remainingTime_);
        }

        setSidelinkGrant(mode4Grant);


        // Need to set the size of our grant to the correct size we need to ask rlc for, i.e. for the sdu size.
        mode4Grant->setGrantedCwBytes((MAX_CODEWORDS - currentCw_), pkt->getBitLength());

        pkt->setControlInfo(lteInfo);
    }*/
    if(rrcState=="RRC_CONN" || rrcState=="RRC_INACTIVE")
    {

        UserControlInfo* lteInfo = check_and_cast< UserControlInfo*>(pkt->removeControlInfo());
        receivedTime_ = NOW;
        double elapsedTime = receivedTime_.dbl() - pkt->getCreationTime();
        double duration = SimTime(pkt->getDuration(), SIMTIME_MS).dbl();
        duration = duration - elapsedTime;
        double dur = duration;
        remainingTime_ = pkt->getDuration() - dur;

        EV<<"Remaining time: "<<remainingTime_<<endl;
        EV<<"Priority: "<<pkt->getPriority()<<endl;
        EV<<"bit length: "<<pkt->getDataSize()<<endl;

        if (schedulingGrant_ != NULL && periodCounter_ > remainingTime_)
        {

            //emit(grantBreakTiming, 1);
            //delete schedulingGrant_;
            //schedulingGrant_ = NULL;
            mode3Grant=   macGenerateSchedulingGrant(remainingTime_, pkt->getPriority(), pkt->getDataSize());
        }
        else if (schedulingGrant_ == NULL)
        {

            mode3Grant= macGenerateSchedulingGrant(remainingTime_, pkt->getPriority(), pkt->getDataSize());

        }
        else
        {

            LteSidelinkGrant* mode3Grant = check_and_cast<LteSidelinkGrant*>(schedulingGrant_);
            mode3Grant->setSpsPriority(pkt->getPriority());
            // Need to get the creation time for this
            mode3Grant->setMaximumLatency(remainingTime_);
        }

        // Need to set the size of our grant to the correct size we need to ask rlc for, i.e. for the sdu size.
        mode3Grant->setGrantedCwBytes((MAX_CODEWORDS - currentCw_), pkt->getDataSize());
        EV<<"Mode3Grant packetId: "<<lteInfo->getPktId();
        mode3Grant->setCamId(lteInfo->getCAMId());
        EV<<"Mode3Grant CAMId: "<<lteInfo->getCAMId();
        //mode3Grant->setPacketId(lteInfo->getPktId());
        slGrant = mode3Grant;
        setSidelinkGrant(slGrant);

        pkt->setControlInfo(lteInfo);
    }

}



void SidelinkConfiguration::handleSelfMessage()
{
    //integrated with LteMacUeD2D::handleSelfMessage();
}

void SidelinkConfiguration::macHandleSps(std::vector<std::tuple<double, int, double>> CSRs, std::string rrcCurrentState)
{
    /* *   This is where we add the subchannels to the actual scheduling grant, so a few things
     * 1. Need to ensure in the self message part that if at any point we have a scheduling grant without assigned subchannels, we have to wait
     * 2. Need to pick at random from the SPS list of CSRs
     * 3. Assign the CR
     * 4. return
     * */


    //SPSResourcePool* candidatesPacket = check_and_cast<SPSResourcePool *>(pkt);
    slGrant = getSidelinkGrant();


    EV<<"Number of CSRs: "<<CSRs.size()<<endl;

    //slGrant = check_and_cast<LteSidelinkGrant*>(schedulingGrant_);

    // Select random element from vector
    int index=0;

    if (CSRs.size()==0)
    {
        EV<<"CSRs size: "<<CSRs.size()<<endl;
        throw cRuntimeError("Cannot allocate CSRs");
    }

    index = intuniform(0, CSRs.size()-1, 1);

    std::tuple<double, int, double> selectedCR = CSRs[index];
    // Gives us the time at which we will send the subframe.


    int initialSubchannel = 0;
    int finalSubchannel = initialSubchannel + slGrant->getNumSubchannels(); // Is this actually one additional subchannel?

    EV<<"initial subchannel: "<<initialSubchannel<<" "<<"final subchannel: "<<finalSubchannel<<endl;
    // Emit statistic about the use of resources, i.e. the initial subchannel and it's length.
    //emit(selectedSubchannelIndex, initialSubchannel);
    //emit(selectedNumSubchannels, slGrant->getNumSubchannels());

    // Determine the RBs on which we will send our message
    RbMap grantedBlocks;
    int totalGrantedBlocks = slGrant->getTotalGrantedBlocks();
    /*for (int i=initialSubchannel;i<finalSubchannel;i++)
    {
        std::vector<Band> allocatedBands;
        for (Band b = i * subchannelSize_; b < (i * subchannelSize_) + subchannelSize_ ; b++)
        {
            grantedBlocks[MACRO][b] = 1;
            ++totalGrantedBlocks;
        }
    }*/

    double startTime= slGrant->getStartTime().dbl();

    slGrant->setPeriodic(true);
    slGrant->setGrantedBlocks(grantedBlocks);
    slGrant->setTotalGrantedBlocks(totalGrantedBlocks);
    slGrant->setDirection(D2D_MULTI);
    slGrant->setCodewords(1);
    slGrant->setStartingSubchannel(initialSubchannel);
    slGrant->setMcs(maxMCSPSSCH_);

    LteMod mod = _QPSK;
    if (maxMCSPSSCH_ > 9 && maxMCSPSSCH_ < 17)
    {
        mod = _16QAM;
    }
    else if (maxMCSPSSCH_ > 16 && maxMCSPSSCH_ < 29 )
    {
        mod = _64QAM;
    }


    EV<<"totalGrantedBlocks: "<<totalGrantedBlocks<<endl;
    setAllocatedBlocksSCIandData(totalGrantedBlocks);
    EV<<"maxMCSPSSCH_: "<<maxMCSPSSCH_<<endl;

    unsigned int i = (mod == _QPSK ? 0 : (mod == _16QAM ? 9 : (mod == _64QAM ? 15 : 0)));

    const unsigned int* tbsVect = itbs2tbs(mod, SINGLE_ANTENNA_PORT0, 1, maxMCSPSSCH_ - i);
    maximumCapacity_ = tbsVect[totalGrantedBlocks-1];

    EV<<"maximum capacity: "<< maximumCapacity_<<endl;
    slGrant->setGrantedCwBytes(currentCw_, maximumCapacity_);
    // Simply flips the codeword.
    currentCw_ = MAX_CODEWORDS - currentCw_;
    periodCounter_= slGrant->getPeriod();
    expirationCounter_= (slGrant->getResourceReselectionCounter() * periodCounter_) + 1;

    EV<<"Sidelink Configuration period counter: "<<periodCounter_<<endl;
    EV<<"Sidelink Configuration expiration counter: "<<expirationCounter_<<endl;
    EV<<"Sidelink Configuration Granted CWBytes size: "<<slGrant->getGrantedCwBytesArraySize()<<endl;
    //Implement methods to store expiration counter and period counter
    slGrant->setPeriodCounter(periodCounter_);
    slGrant->setExpirationCounter(expirationCounter_);
    setSidelinkGrant(slGrant);

    // TODO: Setup for HARQ retransmission, if it can't be satisfied then selection must occur again.


    CSRs.clear();

}

LteSidelinkGrant* SidelinkConfiguration::macGenerateSchedulingGrant(double maximumLatency, int priority, int tbSize)
{
    /**
     * 1. Packet priority
     * 2. Resource reservation interval
     * 3. Maximum latency
     * 4. Number of subchannels
     * 6. Send message to PHY layer looking for CSRs
     */
    EV<<"SidelinkConfiguration::macGenerateSchedulingGrant"<<endl;
    if(rrcCurrentState=="RRC_CONN" ||rrcCurrentState=="RRC_INACTIVE")
    {
        slGrant = new LteSidelinkGrant("LteMode3Grant");
    }

    else
    {
        slGrant = new LteSidelinkGrant("LteMode4Grant");
    }



    // Priority is the most difficult part to figure out, for the moment I will assign it as a fixed value
    slGrant -> setSpsPriority(priority);
    slGrant -> setPeriod(restrictResourceReservationPeriod * 100); //resource reservation interval/Prsvp_TX
    maximumLatency = intuniform(20,100);  //Uniformly varies between 20 ms and 100 ms
    slGrant -> setMaximumLatency(maximumLatency);
    slGrant -> setPossibleRRIs(validResourceReservationIntervals_);
    slGrant->setStartingSubchannel(0);
    int cbrMinSubchannelNum;
    int cbrMaxSubchannelNum;

    std::unordered_map<std::string,double> cbrMap = cbrPSSCHTxConfigList_.at(currentCbrIndex_);

    std::unordered_map<std::string,double>::const_iterator got = cbrMap.find("allowedRetxNumberPSSCH");
    if ( got == cbrMap.end() )
        allowedRetxNumberPSSCH_ = allowedRetxNumberPSSCH_;
    else
        allowedRetxNumberPSSCH_ = std::min((int)got->second, allowedRetxNumberPSSCH_);

    got = cbrMap.find("minSubchannel-NumberPSSCH");
    if ( got == cbrMap.end() )
        cbrMinSubchannelNum = minSubchannelNumberPSSCH_;
    else
        cbrMinSubchannelNum = (int)got->second;

    got = cbrMap.find("maxSubchannel-NumberPSSCH");
    if ( got == cbrMap.end() )
        cbrMaxSubchannelNum = maxSubchannelNumberPSSCH_;
    else
        cbrMaxSubchannelNum = (int)got->second;

    /*
     * Need to pick the number of subchannels for this reservation*/

    int minSubchannelNumberPSSCH;
    int maxSubchannelNumberPSSCH;
    if (maxSubchannelNumberPSSCH_ < cbrMinSubchannelNum || cbrMaxSubchannelNum < minSubchannelNumberPSSCH_)
    {
        // No overlap therefore I will use the cbr values (this is left to the UE, the opposite approach is also entirely valid).
        minSubchannelNumberPSSCH = cbrMinSubchannelNum;
        maxSubchannelNumberPSSCH = cbrMaxSubchannelNum;
    }
    else
    {
        minSubchannelNumberPSSCH = std::max(minSubchannelNumberPSSCH_, cbrMinSubchannelNum);
        maxSubchannelNumberPSSCH = std::min(maxSubchannelNumberPSSCH_, cbrMaxSubchannelNum);
    }

    // Selecting the number of subchannel at random as there is no explanation as to the logic behind selecting the resources in the range unlike when selecting MCS.
    int numSubchannels = intuniform(minSubchannelNumberPSSCH, maxSubchannelNumberPSSCH);

    slGrant -> setNumberSubchannels(maxSubchannelNumberPSSCH);

    // Based on restrictResourceReservation interval But will be between 1 and 15
    // Again technically this needs to reconfigurable as well. But all of that needs to come in through ini and such.

    resourceReselectionCounter_ = intuniform(5, 15); // Beacuse RRI = 100ms

    slGrant -> setResourceReselectionCounter(resourceReselectionCounter_);
    slGrant -> setExpiration(resourceReselectionCounter_ * restrictResourceReservationPeriod);
    slGrant->setTransmitBlockSize(tbSize);

    LteSidelinkGrant* phyGrant = slGrant;

    LteMacBase* mac=check_and_cast<LteMacBase*>(getParentModule()->getSubmodule("mac"));
    UserControlInfo* uinfo = new UserControlInfo();

    uinfo->setSourceId(mac->getMacNodeId());
    uinfo->setDestId(mac->getMacNodeId());
    uinfo->setFrameType(SIDELINKGRANT);

    phyGrant->setDirection(D2D_MULTI);
    phyGrant->setControlInfo(uinfo);

    mac->sendLowerPackets( phyGrant);
    schedulingGrant_ = slGrant;
    //emit(grantRequest, 1);
    emit(grantStartTime,80);
    setSidelinkGrant(slGrant);
    return slGrant;

}

void SidelinkConfiguration::flushHarqBuffers(HarqTxBuffers harqTxBuffers_, LteSidelinkGrant* grant)
{
    // send the selected units to lower layers
    // First make sure packets are sent down
    // HARQ retrans needs to be taken into account
    // Maintain unit list maybe and that causes retrans?
    // But purge them once all messages sent.

    slGrant = grant;

    //slGrant = dynamic_cast<LteSidelinkGrant*>(schedulingGrant_);

    HarqTxBuffers::iterator it2;
    EV<<"Harq size: "<<harqTxBuffers_.size()<<endl;
    EV<<"Scheduling grant: "<<slGrant<<endl;

    for(it2 = harqTxBuffers_.begin(); it2 != harqTxBuffers_.end(); it2++)
    {
        EV<<"SidelinkConfiguration::flushHarqBuffers for: "<<it2->second->isSelected()<<endl;


        std::unordered_map<std::string,double> cbrMap = cbrPSSCHTxConfigList_.at(currentCbrIndex_);
        std::unordered_map<std::string,double>::const_iterator got;


        if (packetDropping_) {
            throw cRuntimeError("debug 1");
            double crLimit;
            got = cbrMap.find("cr-Limit");
            if (got == cbrMap.end())
                crLimit = 1;
            else
                crLimit = got->second;

            if (channelOccupancyRatio_ > crLimit) {
                throw cRuntimeError("debug 2");
                // Need to drop the unit currently selected
                UnitList ul = it2->second->firstAvailable();
                it2->second->forceDropProcess(ul.first);
                //emit(packetDropDCC, 1);
            }
        }


        if (it2->second->isSelected())
        {
            //throw cRuntimeError("debug 3");
            LteHarqProcessTx* selectedProcess = it2->second->getSelectedProcess();

            for (int cw=0; cw<MAX_CODEWORDS; cw++)
            {

                int pduLength = selectedProcess->getPduLength(cw);
                EV<<"PDU length: "<<pduLength<<endl;
                emit(dataSize,pduLength);
                //throw cRuntimeError("debug 4");
                if ( pduLength > 0)
                {
                    int cbrMinMCS;
                    int cbrMaxMCS;

                    got = cbrMap.find("minMCS-PSSCH");
                    if ( got == cbrMap.end() )
                        cbrMinMCS = minMCSPSSCH_;
                    else
                        cbrMinMCS = (int)got->second;

                    got = cbrMap.find("maxMCS-PSSCH");

                    if ( got == cbrMap.end() )
                        cbrMaxMCS = maxMCSPSSCH_;
                    else
                        cbrMaxMCS = (int)got->second;

                    int minMCS;
                    int maxMCS;

                    if (maxMCSPSSCH_ < cbrMinMCS || cbrMaxMCS < minMCSPSSCH_)
                    {
                        // No overlap therefore I will use the cbr values (this is left to the UE).
                        minMCS = cbrMinMCS;
                        maxMCS = cbrMaxMCS;
                    }
                    else
                    {
                        minMCS = std::max(minMCSPSSCH_, cbrMinMCS);
                        maxMCS = std::min(maxMCSPSSCH_, cbrMaxMCS);
                    }

                    bool foundValidMCS = false;
                    int totalGrantedBlocks =  slGrant->getTotalGrantedBlocks();
                    EV<<"totalGrantedBlocks: "<<totalGrantedBlocks<<endl;

                    int mcsCapacity = 0;
                    for (int mcs=minMCS; mcs < maxMCS; mcs++)
                    {
                        LteMod mod = _QPSK;
                        if (maxMCSPSSCH_ > 9 && maxMCSPSSCH_ < 17)
                        {
                            mod = _16QAM;
                        }
                        else if (maxMCSPSSCH_ > 16 && maxMCSPSSCH_ < 29 )
                        {
                            mod = _64QAM;
                        }

                        unsigned int i = (mod == _QPSK ? 0 : (mod == _16QAM ? 9 : (mod == _64QAM ? 15 : 0)));

                        const unsigned int* tbsVect = itbs2tbs(mod, SINGLE_ANTENNA_PORT0, 1, mcs - i);
                        mcsCapacity = tbsVect[totalGrantedBlocks-1];
                        EV<<" mcsCapacity: "<< mcsCapacity <<endl;


                            EV<<"Valid MCS found: "<<endl;
                            foundValidMCS = true;

                            slGrant->setMcs(mcs);

                            slGrant->setGrantedCwBytes(cw, mcsCapacity);

                            if (! slGrant->getUserTxParams())
                            {
                                slGrant->setUserTxParams(preconfiguredTxParams_);
                            }

                            /*  LteSidelinkGrant* phyGrant =  slGrant;

                            LteMacBase* mac=check_and_cast<LteMacBase*>(getParentModule()->getSubmodule("mac"));
                            UserControlInfo* uinfo = new UserControlInfo();



                            uinfo->setSourceId(nodeId_);

                            uinfo->setDestId(mac->getMacNodeId());

                            uinfo->setFrameType(GRANTPKT);
                            uinfo->setTxNumber(1);
                            uinfo->setDirection(D2D_MULTI);

                            uinfo->setUserTxParams(preconfiguredTxParams_);
                            uinfo->setSubchannelNumber(slGrant->getStartingSubchannel());
                            uinfo->setSubchannelLength(slGrant->getNumSubchannels());
                            uinfo->setGrantStartTime(slGrant->getStartTime());*/

                            //phyGrant->setControlInfo(uinfo);

                            // Send Grant to PHY layer for sci creation
                            //mac->sendLowerPackets(phyGrant);

                            // Send pdu to PHY layer for sending.
                            it2->second->sendSelectedDown();

                            // Log transmission to A calculation log
                            previousTransmissions_[NOW.dbl()] =  slGrant->getNumSubchannels();

                            missedTransmissions_ = 0;

                            //emit(selectedMCS, mcs);
                            EV<<"VALID MCS: "<<foundValidMCS<<endl;


                    }
                    if (!foundValidMCS)
                    {
                        //throw cRuntimeError("debug 5");
                        // Never found an MCS to satisfy the requirements of the message must regenerate grant
                        //slGrant = check_and_cast<LteSidelinkGrant*>(schedulingGrant_);
                        int priority =  slGrant->getSpsPriority();
                        int latency =  slGrant->getMaximumLatency();
                        simtime_t elapsedTime = NOW - receivedTime_;
                        remainingTime_ -= elapsedTime.dbl();

                        //emit(grantBreakSize, pduLength);
                        //emit(maximumCapacity, mcsCapacity);

                        if (remainingTime_ <= 0)
                        {
                            //emit(droppedTimeout, 1);
                            selectedProcess->forceDropProcess();
                            delete schedulingGrant_;
                            schedulingGrant_ = NULL;
                        }
                        else
                        {
                            delete schedulingGrant_;
                            schedulingGrant_ = NULL;
                            macGenerateSchedulingGrant(remainingTime_, priority, 0);
                        }
                    }
                }
                break;
            }
        }
        else
        {

            // if no transmission check if we need to break the grant.
            ++missedTransmissions_;
            //emit(missedTransmission, 1);

            /* LteSidelinkGrant* phyGrant =  slGrant->dup();
            phyGrant->setSpsPriority(0);


            UserControlInfo* uinfo = new UserControlInfo();
            uinfo->setSourceId(nodeId_);
            uinfo->setDestId(nodeId_);
            uinfo->setFrameType(GRANTPKT);
            uinfo->setTxNumber(1);
            uinfo->setDirection(D2D_MULTI);
            uinfo->setUserTxParams(preconfiguredTxParams_);

            phyGrant->setControlInfo(uinfo);*/
            /*
            if (missedTransmissions_ >= reselectAfter_)
            {
                phyGrant->setPeriod(0);
                phyGrant->setExpiration(0);

                //delete schedulingGrant_;
                schedulingGrant_ = NULL;
                missedTransmissions_ = 0;
                //emit(grantBreakMissedTrans, 1);
            }*/

            // Send Grant to PHY layer for sci creation
            /*            LteMacBase* mac = dynamic_cast<LteMacBase*>(getParentModule()->getSubmodule("mac"));
            mac->sendLowerPackets(phyGrant);*/
        }

    }
    if (expiredGrant_) {
        // Grant has expired, only generate new grant on receiving next message to be sent.
        delete schedulingGrant_;
        schedulingGrant_ = NULL;
        expiredGrant_ = false;
    }

}

void SidelinkConfiguration::finish()
{

}

void SidelinkConfiguration::setSidelinkGrant(LteSidelinkGrant* slGrant)
{
    slGrant = slGrant;
}

void SidelinkConfiguration::setAllocatedBlocksSCIandData(int totalGrantedBlocks)
{
    allocatedBlocksSCIandData = totalGrantedBlocks;
}
