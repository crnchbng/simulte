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

#ifndef __ARTERY_LTESIDELINKGRANT_H_
#define __ARTERY_LTESIDELINKGRANT_H_

#include <omnetpp.h>
#include "stack/mac/packet/LteSchedulingGrant.h"
using namespace omnetpp;

/**
 * TODO - Generated class
 */
class LteSidelinkGrant : public LteSchedulingGrant
{
protected:
    simtime_t startTime;
    std::vector<double> possibleRRIs;
    bool retransmission;
    bool firstTransmission;
    unsigned int timeGapTransRetrans;
    unsigned int spsPriority;
    unsigned int numSubchannels;
     double maximumLatency;
    unsigned int startingSubchannel;
    unsigned int mcs;
    unsigned int retransSubchannel; // It is possible the retransmission has different resources assigned to it.
    unsigned int resourceReselectionCounter;
    int transmitBlockSize;
    unsigned int periodCounter;
    unsigned int expirationCounter;
    int packetId;
    int CAMId;
    MacNodeId destId;


public:

    LteSidelinkGrant(const char *name = NULL, int kind = 0) :
        LteSchedulingGrant(name, kind)
    {
        numSubchannels = 0;
        spsPriority = 0;
        maximumLatency = 0.0;
        timeGapTransRetrans = 0;
        startingSubchannel = 0;
        mcs = 0;
        retransSubchannel = 0;
        resourceReselectionCounter = 0;
        firstTransmission = true;
        startTime = simTime();
        packetId = 0;
        CAMId = 0;
    }


    ~LteSidelinkGrant()
    {
    if (userTxParams != NULL)
            {
                delete userTxParams;
                userTxParams = NULL;
            }
    }
    LteSidelinkGrant(const LteSidelinkGrant& other) :
        LteSchedulingGrant(other.getName())
    {
        operator=(other);
    }

    LteSidelinkGrant& operator=(const LteSidelinkGrant& other)
    {
        numSubchannels = other.numSubchannels;
        spsPriority = other.spsPriority;
        startTime = other.startTime;
        maximumLatency = other.maximumLatency;
        timeGapTransRetrans = other.timeGapTransRetrans;
        startingSubchannel = other.startingSubchannel;
        mcs = other.mcs;
        retransSubchannel = other.retransSubchannel;
        resourceReselectionCounter = other.resourceReselectionCounter;
        possibleRRIs = other.possibleRRIs;
        destId = other.destId;
        periodCounter = other.periodCounter;
        expirationCounter = other.expirationCounter;
        packetId = other.packetId;
        CAMId  = other.CAMId;
        LteSchedulingGrant::operator=(other);
        return *this;
    }

    virtual LteSidelinkGrant *dup() const
    {
        return new LteSidelinkGrant(*this);
    }

    void setStartTime(simtime_t start)
    {
        startTime = start;
    }
    simtime_t getStartTime() const
    {
        return startTime;
    }
    void setSpsPriority(unsigned int priority)
    {
        spsPriority = priority;
    }
    unsigned int getSpsPriority() const
    {
        return spsPriority;
    }
    void setNumberSubchannels(unsigned int subchannels)
    {
        numSubchannels = subchannels;
    }
    unsigned int getNumSubchannels() const
    {
        return numSubchannels;
    }
    void setMaximumLatency(unsigned int maxLatency)
    {
        maximumLatency = maxLatency;
    }
    unsigned int getMaximumLatency() const
    {
        return maximumLatency;
    }
    void setTimeGapTransRetrans(unsigned int timeGapTransRetrans)
    {
        this->timeGapTransRetrans = timeGapTransRetrans;
    }
    unsigned int getTimeGapTransRetrans() const
    {
        return timeGapTransRetrans;
    }
    void setStartingSubchannel(unsigned int subchannelIndex)
    {
        this->startingSubchannel = subchannelIndex;
    }
    unsigned int getStartingSubchannel() const
    {
        return startingSubchannel;
    }
    void setMcs(unsigned int mcs)
    {
        this->mcs = mcs;
    }
    unsigned int getMcs() const
    {
        return mcs;
    }

    void setTransmitBlockSize(int tbSize)
        {

            this->transmitBlockSize = tbSize;
        }
    int getTransmitBlockSize()
    {
        return transmitBlockSize;
    }

    void setRetransSubchannel(unsigned int retransSubchannel)
    {
        this->retransSubchannel = retransSubchannel;
    }
    unsigned int getRetransSubchannel() const
    {
        return retransSubchannel;
    }
    void setResourceReselectionCounter(unsigned int resourceReselectionCounter)
    {
        this->resourceReselectionCounter = resourceReselectionCounter;
    }
    unsigned int getResourceReselectionCounter() const
    {
        return resourceReselectionCounter;
    }
    void setRetransmission(bool retransmission)
    {
        this->retransmission = retransmission;
    }
    bool getRetransmission() const
    {
        return retransmission;
    }
    std::vector<double> getPossibleRRIs()
    {
        return possibleRRIs;
    }
    void setPossibleRRIs(std::vector<double> RRIs)
    {
        this->possibleRRIs = RRIs;
    }
    bool getFirstTransmission() const
    {
        return firstTransmission;
    }
    void setFirstTransmission(bool firstTransmission)
    {
        this->firstTransmission = firstTransmission;
    }

    MacNodeId getDestId() const {
        return destId;
    }

    void setDestId(MacNodeId destId) {
        this->destId = destId;
    }

    unsigned int getExpirationCounter() {
        return expirationCounter;
    }

    void setExpirationCounter(unsigned int expirationCounter) {
        this->expirationCounter = expirationCounter;
    }

    unsigned int getPeriodCounter() {
        return periodCounter;
    }

    void setPeriodCounter(unsigned int periodCounter) {
        this->periodCounter = periodCounter;
    }
    void setPacketId(int pid)
    {
        this->packetId = pid;
    }
    int getPacketId()
    {
        return packetId;
    }

    int getCamId()  {
        return CAMId;
    }

    void setCamId(int camId) {
        CAMId = camId;
    }
};





#endif
