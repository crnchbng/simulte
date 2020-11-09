#ifndef __ARTERY_DataArrival_H_
#define __ARTERY_DataArrival_H_

#include <omnetpp/cmessage.h>
#include "common/LteCommon.h"
#include "stack/mac/packet/DataArrival_m.h"

class DataArrival: public DataArrival_Base
{
protected:
    double creationTime;
    double duration;
    int priority;
    int dataSize;



public:

    DataArrival(const char *name = NULL, int kind = 0) :
        DataArrival_Base(name, kind)
{
}

    ~DataArrival()
    {
    }

    DataArrival(const DataArrival& other)
    {
        operator=(other);
    }

    DataArrival& operator=(const DataArrival& other)
    {
        creationTime = other.creationTime;
        duration = other.duration;
        priority = other.priority;
        dataSize = other.dataSize;

        DataArrival_Base::operator=(other);
        return *this;
    }

    virtual DataArrival *dup() const
    {
        return new DataArrival(*this);
    }

    virtual double getCreationTime() const {
        return creationTime;
    }

    virtual void setCreationTime(double creationTime) {
        this->creationTime = creationTime;
    }

    virtual int getDataSize() const {
        return dataSize;
    }

    virtual void setDataSize(int dataSize) {
        this->dataSize = dataSize;
    }

    virtual double getDuration() const {
        return duration;
    }

    virtual void setDuration(double duration) {
        this->duration = duration;
    }

    virtual int getPriority() const {
        return priority;
    }

    virtual void setPriority(int priority) {
        this->priority = priority;
    }
};

#endif



