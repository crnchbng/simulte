


#include <omnetpp/cmessage.h>
#include "control/packet/MIBSLRequest_m.h"
#include <omnetpp.h>

class MIBSL: public MIBSLRequest_Base{
protected:

    int slBandwidth;
    bool cellFound;
    int directFrameNumber;
    int directSubFrameNumber;

    double nextMIBTransmission;
    omnetpp::simtime_t timestamp;
public:

    MIBSL(const char *name = NULL, int kind = 0) :
        MIBSLRequest_Base(name, kind)
{
}

    ~MIBSL()
    {
    }

    MIBSL(const MIBSL& other)
    {
        operator=(other);
    }

    MIBSL& operator=(const MIBSL& other)
    {
        slBandwidth = other.slBandwidth;
        cellFound = other.cellFound;
        directFrameNumber = other.directFrameNumber;
        directSubFrameNumber = other.directSubFrameNumber;
        timestamp = other.timestamp;
        MIBSLRequest_Base::operator=(other);
        return *this;
    }

    virtual MIBSL *dup() const
    {
        return new MIBSL(*this);
    }


    // field getter/setter methods
    virtual int getSlBandwidth(){
        return slBandwidth;
    }
    virtual void setSlBandwidth(int slBandwidth){
        this->slBandwidth = slBandwidth;
    }
    virtual bool getCellFound()
    {
        return cellFound;
    }
    virtual void setCellFound(bool cellFound){
        this->cellFound = cellFound;
    }
    virtual int getDirectFrameNumber() {
        return directFrameNumber;
    }
    virtual void setDirectFrameNumber(int directFrameNumber)
    {
        this->directFrameNumber = directFrameNumber;
    }
    virtual int getDirectSubFrameNumber()
    {
        return directFrameNumber;
    }
    virtual void setDirectSubFrameNumber(int directSubFrameNumber)
    {
        this->directSubFrameNumber = directSubFrameNumber;
    }
    virtual ::omnetpp::simtime_t getTimestamp() {
        return timestamp;
    }
    virtual void setTimestamp(::omnetpp::simtime_t timestamp){
        this->timestamp = timestamp;
    }

    virtual void setnextMIBTransmission(double nextMIBTransmission)
    {
        this->nextMIBTransmission = nextMIBTransmission;
    }

    virtual double getNextMIBTransmission()
    {
        return nextMIBTransmission;
    }
};



