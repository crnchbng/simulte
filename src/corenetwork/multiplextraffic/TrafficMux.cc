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

#include "TrafficMux.h"

Define_Module(TrafficMux);

void TrafficMux::initialize()
{
    //Initialize the gates
    IPInput = gate("IPInput");
    IPOutput = gate("IPOutput");
    nonIPInput = gate("nonIPInput");
    nonIPOutput = gate("nonIPOutput");
}

void TrafficMux::handleMessage(cMessage *msg)
{
    cPacket* pkt = check_and_cast<cPacket *>(msg);
       EV << "TrafficMux : Received packet " << pkt->getName() <<
       " from port " << pkt->getArrivalGate()->getName() << endl;

       cGate* incoming = pkt->getArrivalGate();
       if (incoming == IPInput)
       {
           handleUpperIPTraffic(pkt);
       }
       else if (incoming == nonIPInput)
       {
           handleUpperNonIPTraffic(pkt);
       }
       return;
}

void TrafficMux::handleUpperIPTraffic(cPacket *pkt){
  send(pkt,IPOutput);

}

void TrafficMux::handleUpperNonIPTraffic(cPacket *pkt){
send(pkt, nonIPOutput);
}
