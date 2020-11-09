


#include <omnetpp/cmessage.h>
#include "stack/mac/packet/SPSResourcePoolMode3_m.h"
#include "common/LteCommon.h"
#include "stack/mac/packet/LteSidelinkGrant.h"
class SPSResourcePoolMode3: public SPSResourcePoolMode3_Base
{
  protected:

    std::vector<std::tuple<double, int, double>> CSRs;
    MacNodeId destId;
    LteSidelinkGrant* mode3grant;
  public:

    SPSResourcePoolMode3(const char *name = NULL, int kind = 0) :
        SPSResourcePoolMode3_Base(name, kind)
    {
    }

    ~SPSResourcePoolMode3()
    {
    }

    SPSResourcePoolMode3(const SPSResourcePoolMode3& other)
    {
        operator=(other);
    }

    SPSResourcePoolMode3& operator=(const SPSResourcePoolMode3& other)
    {
        CSRs = other.CSRs;
        destId= other.destId;
        mode3grant = other.mode3grant;
        SPSResourcePoolMode3_Base::operator=(other);
        return *this;
    }

    virtual SPSResourcePoolMode3 *dup() const
    {
        return new SPSResourcePoolMode3(*this);
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

    virtual  LteSidelinkGrant* getMode3grant() {
        return mode3grant;
    }

    virtual void setMode3grant(LteSidelinkGrant* mode3grant) {
        this->mode3grant = mode3grant;
    }
};



