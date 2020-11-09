


#include <omnetpp/cmessage.h>
#include "control/packet/RRCConnSetUp_m.h"

class RRCConnSetUp: public RRCConnSetUp_Base
{
  protected:

    bool cellFound;
    bool connSetUp;

  public:

    RRCConnSetUp(const char *name = NULL, int kind = 0) :
        RRCConnSetUp_Base(name, kind)
    {
    }

    ~RRCConnSetUp()
    {
    }

    RRCConnSetUp(const RRCConnSetUp& other)
    {
        operator=(other);
    }

    RRCConnSetUp& operator=(const RRCConnSetUp& other)
    {
        cellFound = other.cellFound;
        connSetUp = other.connSetUp;
        RRCConnSetUp_Base::operator=(other);
        return *this;
    }

    virtual RRCConnSetUp *dup() const
    {
        return new RRCConnSetUp(*this);
    }

    virtual void setCellfound(bool cellFound )
    {
        this->cellFound = cellFound;
    }

    virtual void setConnSetUp(bool connSetUp)
    {
        this->connSetUp = connSetUp;
    }

    virtual bool getCellFound()
    {
        return cellFound;
    }

    virtual bool getConnSetUp()
    {
        return connSetUp;
    }
};



