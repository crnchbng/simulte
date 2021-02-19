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

#ifndef __ARTERY_ALERTNONIP_H_
#define __ARTERY_ALERTNONIP_H_

#include <omnetpp.h>
#include "apps/nonip/AlertNonIpPacket_m.h"
#include "corenetwork/binder/LteBinder.h"
#include "apps/nonip/NonIpBase.h"
using namespace omnetpp;
using namespace inet;
/**
 * TODO - Generated class
 */
class AlertNonIp : public NonIpBase
{
public:
    ~AlertNonIp() override;
protected:
    int size_;
    int nextSno_;
    int priority_;
    int duration_;
    simtime_t period_;

    simsignal_t sentMsg_;
    simsignal_t delay_;
    simsignal_t rcvdMsg_;
    simsignal_t cbr_;

    cMessage *selfSender_;

    LteBinder* binder_;
    MacNodeId nodeId_;

    int numInitStages() const { return inet::NUM_INIT_STAGES; }

    /**
     * Grabs NED parameters, initializes gates
     * and the TTI self message
     */
    void initialize(int stage);

    void handleLowerMessage(cMessage* msg);


    /**
     * Statistics recording
     */
    void finish();

    /**
     * Main loop of the Mac level, calls the scheduler
     * and every other function every TTI : must be reimplemented
     * by derivate classes
     */
    void handleSelfMessage(cMessage* msg);

    /**
     * sendLowerPackets() is used
     * to send packets to lower layer
     *
     * @param pkt Packet to send
     */
    void sendLowerPackets(cPacket* pkt);
};

#endif
