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

#ifndef __ARTERY_TRAFFICMUX_H_
#define __ARTERY_TRAFFICMUX_H_

#include <omnetpp.h>

using namespace omnetpp;

/**
 * TODO - Generated class
 */
class TrafficMux : public cSimpleModule
{
  protected:
    virtual void initialize();
    virtual void handleMessage(cMessage *msg);
  private:
    /*
     * Upper Layer Handler
     */

    /**
     * handler for IP/Non-IP traffic from upper layer
     *
     * @param pkt packet to process
     */
    void handleUpperIPTraffic(cPacket *pkt);
    void handleUpperNonIPTraffic(cPacket *pkt);
    /*
     * Lower Layer Handler
     */

    /**
     * handler for mac2rlc packets
     *
     * @param pkt packet to process
     */
    void mac2rlc(cPacket *pkt);

    /*
     * Data structures
     */

    cGate* IPInput;
    cGate* IPOutput;
    cGate* nonIPInput;
    cGate* nonIPOutput;
};

#endif
