


#include <omnetpp/cmessage.h>
#include "stack/mac/packet/SPSResourcePoolMode4_m.h"
#include "common/LteCommon.h"
#include "stack/mac/packet/LteSidelinkGrant.h"
class SPSResourcePoolMode4: public SPSResourcePoolMode4_Base
{
  protected:

    std::vector<std::tuple<double, int, double>> CSRs;
    MacNodeId destId;
    LteSidelinkGrant* mode4grant;
  public:

    SPSResourcePoolMode4(const char *name = NULL, int kind = 0) :
        SPSResourcePoolMode4_Base(name, kind)
    {
    }

    ~SPSResourcePoolMode4()
    {
    }

    SPSResourcePoolMode4(const SPSResourcePoolMode4& other)
    {
        operator=(other);
    }

    SPSResourcePoolMode4& operator=(const SPSResourcePoolMode4& other)
    {
        CSRs = other.CSRs;
        destId= other.destId;
        mode4grant = other.mode4grant;
        SPSResourcePoolMode4_Base::operator=(other);
        return *this;
    }

    virtual SPSResourcePoolMode4 *dup() const
    {
        return new SPSResourcePoolMode4(*this);
    }

    virtual void setCSRs(const std::vector<std::tuple<double, int, double>> CSRs )
    {
        this->CSRs = CSRs;
    }

    virtual std::vector<std::tuple<double, int, double>> getCSRs()
    {
        return CSRs;
    }

    virtual MacNodeId getDestId() const {
        return destId;
    }

    virtual void setDestId(MacNodeId destId) {
        this->destId = destId;
    }

    virtual  LteSidelinkGrant* getMode4grant() {
        return mode4grant;
    }

    virtual void setMode4grant(LteSidelinkGrant* mode4grant) {
        this->mode4grant = mode4grant;
    }
};



