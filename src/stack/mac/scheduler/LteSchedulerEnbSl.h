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

#ifndef __ARTERY_LTESCHEDULERENBSL_H_
#define __ARTERY_LTESCHEDULERENBSL_H_

#include "stack/mac/scheduler/LcgScheduler.h"
#include "stack/mac/layer/LteMacEnb.h"
#include "stack/mac/packet/LteSidelinkGrant.h"
#include "common/LteCommon.h"
#include "stack/mac/allocator/LteAllocationModule.h"

/**
 * @class LteSchedulerEnbSl
 */

class LteMacEnbD2D;

class LteSchedulerEnbSl: public LcgScheduler
{
protected:
    // Reference to the LTE Binder
    LteBinder *binder_;

    // System allocator, carries out the block-allocation functions.
    LteAllocationModule *allocator_;
    LcgScheduler* lcgScheduler_;
    // Schedule List
    LteMacScheduleList scheduleList_;

    // Scheduled Bytes List
    LteMacScheduleList scheduledBytesList_;
public:
    LteMacEnbD2D* macd2d_;
    /**
     * Default constructor.
     */
    LteSchedulerEnbSl(LteMacEnbD2D * mac);

    /**
     * Destructor.
     */
    virtual ~LteSchedulerEnbSl();


    /* Executes the LCG scheduling algorithm
     * @param availableBytes
     * @return # of scheduled sdus per cid
     */

    LteSidelinkGrant* slGrant;
    LteSchedulingGrant* lteGrant;

    virtual LteMacScheduleList* schedule(LteSidelinkGrant* slgrant);
};
#endif
