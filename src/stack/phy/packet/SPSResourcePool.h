#ifndef RADIODRIVERPROPERTIES_H_4GALJBTN
#define RADIODRIVERPROPERTIES_H_4GALJBTN


#include <omnetpp/cmessage.h>
#include "stack/phy/packet/SPSResourcePool_m.h"
#include "stack/mac/packet/LteSchedulingGrant.h"
#include "common/LteCommon.h"
#include "stack/phy/resources/Subchannel.h"

class SPSResourcePool: public SPSResourcePool_Base
{
  protected:

    std::vector<std::tuple<double, int, double>> CSRs;
    int allocatedBlocksSCIandDataPrevious;

  public:

    SPSResourcePool(const char *name = NULL, int kind = 0) :
        SPSResourcePool_Base(name, kind)
    {
    }

    ~SPSResourcePool()
    {
    }

    SPSResourcePool(const SPSResourcePool& other)
    {
        operator=(other);
    }

    SPSResourcePool& operator=(const SPSResourcePool& other)
    {
        CSRs = other.CSRs;
        allocatedBlocksSCIandDataPrevious = other.allocatedBlocksSCIandDataPrevious;
        SPSResourcePool_Base::operator=(other);
        return *this;
    }

    virtual SPSResourcePool *dup() const
    {
        return new SPSResourcePool(*this);
    }

    virtual void setCSRs(const std::vector<std::tuple<double, int, double>> CSRs )
    {
        this->CSRs = CSRs;
    }

    virtual std::vector<std::tuple<double, int, double>> getCSRs()
    {
        return CSRs;
    }

    int getAllocatedBlocksScIandDataPrevious() const
    {
        return allocatedBlocksSCIandDataPrevious;
    }

    void setAllocatedBlocksScIandDataPrevious(int allocatedBlocksScIandDataPrevious)
    {
        allocatedBlocksSCIandDataPrevious = allocatedBlocksScIandDataPrevious;
    }
};

#endif /* RADIODRIVERPROPERTIES_H_4GALJBTN */

