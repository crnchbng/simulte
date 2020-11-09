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

#include "stack/mac/scheduler/LteSchedulerEnbSl.h"
#include "stack/mac/buffer/LteMacBuffer.h"
#include "stack/mac/layer/LteMacUeD2D.h"
#include "stack/mac/amc/UserTxParams.h"
#include "stack/mac/packet/LteSchedulingGrant.h"
#include "stack/mac/packet/LteMacPdu.h"
#include "stack/mac/scheduler/LcgScheduler.h"
#include "stack/mac/configuration/SidelinkConfiguration.h"
LteSchedulerEnbSl::LteSchedulerEnbSl(LteMacEnbD2D* mac)
:LcgScheduler(mac)
{
    macd2d_=mac;
    slGrant=NULL;
    lcgScheduler_ = new LcgScheduler(macd2d_);

}

LteSchedulerEnbSl::~LteSchedulerEnbSl()
{
    // TODO Auto-generated destructor stub
    delete lteGrant;
    delete slGrant;
    delete lcgScheduler_;
}


LteMacScheduleList* LteSchedulerEnbSl::schedule(LteSidelinkGrant* slgrant)
{

    /* clean up old schedule decisions
     for each cid, this map will store the the amount of sent data (in SDUs)
     */
    scheduleList_.clear();

    /*
     * Clean up scheduling support status map
     */
    statusMap_.clear();

    //Obtain information from Sidelink Grant
    // get the grant

    LteSidelinkGrant* slGrant = slgrant;
    EV<<"Sidelink grant: "<<slGrant<<endl;

    Direction grantDir = slGrant->getDirection();
    EV<<"Direction: "<<slGrant->getDirection()<<endl;
    // get the nodeId of the mac owner node
    MacNodeId nodeId = macd2d_->getMacNodeId();



    unsigned int codewords = slGrant->getCodewords();
    EV<<"LteSchedulerEnbSl::schedule codewords: "<<codewords<<endl;
    EV << NOW << " LteSchedulerEnbSl::schedule - Scheduling node " << nodeId << endl;



    // TODO get the amount of granted data per codeword
    //unsigned int availableBytes = grant->getGrantedBytes();

    unsigned int availableBlocks = slGrant->getTotalGrantedBlocks();
    // TODO check if HARQ ACK messages should be subtracted from available bytes
    EV<<"LteSchedulerEnbSl::schedule Available blocks: "<<availableBlocks<<endl;
    for (Codeword cw = 0; cw < codewords; ++cw)
        {
            unsigned int availableBytes = slGrant->getGrantedCwBytes(cw);

            EV << NOW << " LteSchedulerEnbSl::schedule - Node " << macd2d_->getMacNodeId() << " available data from grant are "
               << " blocks " << availableBlocks << " [" << availableBytes << " - Bytes]  on codeword " << cw << endl;

            // per codeword LCP scheduler invocation

            // invoke the schedule() method of the attached LCP scheduler in order to schedule
            // the connections provided
            std::map<MacCid, unsigned int>& sdus = lcgScheduler_->schedule(availableBytes, grantDir);
            EV<<"LteSchedulerEnbSl::schedule sdu size: "<<sdus.size()<<endl;
            // get the amount of bytes scheduled for each connection
            std::map<MacCid, unsigned int>& bytes = lcgScheduler_->getScheduledBytesList();
            EV<<"LteSchedulerEnbSl::schedule bytes size: "<<bytes.size()<<endl;
            // TODO check if this jump is ok
            if (sdus.empty())
                continue;

            std::map<MacCid, unsigned int>::const_iterator it = sdus.begin(), et = sdus.end();
            for (; it != et; ++it)
            {
                // set schedule list entry
                std::pair<MacCid, Codeword> schedulePair(it->first, cw);
                scheduleList_[schedulePair] = it->second;
            }

            std::map<MacCid, unsigned int>::const_iterator bit = bytes.begin(), bet = bytes.end();
            for (; bit != bet; ++bit)
            {
                // set schedule list entry
                std::pair<MacCid, Codeword> schedulePair(bit->first, cw);
                scheduledBytesList_[schedulePair] = bit->second;
            }

            MacCid highestBackloggedFlow = 0;
            MacCid highestBackloggedPriority = 0;
            MacCid lowestBackloggedFlow = 0;
            MacCid lowestBackloggedPriority = 0;
            bool backlog = false;

            /*// get the highest backlogged flow id and priority
            backlog = macd2d_->getHighestBackloggedFlow(highestBackloggedFlow, highestBackloggedPriority);

            if (backlog) // at least one backlogged flow exists
            {
                // get the lowest backlogged flow id and priority
                macd2d_->getLowestBackloggedFlow(lowestBackloggedFlow, lowestBackloggedPriority);
            }*/

            // TODO make use of above values
        }

    return &scheduleList_;
}
