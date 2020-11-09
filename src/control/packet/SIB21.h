#ifndef __ARTERY_SIB21_H_
#define __ARTERY_SIB21_H_

#include <omnetpp/cmessage.h>
#include "common/LteCommon.h"
#include "control/packet/SIB21Request_m.h"

class SIB21: public SIB21Request_Base
{
  protected:
    int SlOffsetIndicator;
    std::vector<int> subframeBitMap;
    bool adjacencyPSCCHPSSCH;
    int sizeSubchannel; /*{numPRB4,numPRB5,numPRB6,numPRB8,numPRB9,numPRB10,numPRB12,
    numPRB15,numPRB16,numPRB18,numPRB20,numPRB25,numPRB30,numPRB48,numPRB50,numPRB72,
    numPRB75,numPRB96,numPRB100,sparenumPRB1,sparenumPRB2,sparenumPRB3,sparenumPRB4,sparenumPRB5,sparenumPRB6,
    sparenumPRB7,sparenumPRB8,sparenumPRB9,sparenumPRB10,sparenumPRB11,sparenumPRB12,sparenumPRB13};*/
    int numSubchannel;//{sub1,sub3,sub5,sub8,sub10,sub15,sub20,spareSub1};
    int startRBSubchannel;


  public:

    SIB21(const char *name = NULL, int kind = 0) :
        SIB21Request_Base(name, kind)
    {
    }

    ~SIB21()
    {
    }

    SIB21(const SIB21& other)
    {
        operator=(other);
    }

    SIB21& operator=(const SIB21& other)
    {
        SlOffsetIndicator = other.SlOffsetIndicator;
        subframeBitMap = other.subframeBitMap;
        adjacencyPSCCHPSSCH = other.adjacencyPSCCHPSSCH;
        sizeSubchannel = other.sizeSubchannel;
        numSubchannel = other.numSubchannel;
        startRBSubchannel = other.startRBSubchannel;
        SIB21Request_Base::operator=(other);
        return *this;
    }

    virtual SIB21 *dup() const
    {
        return new SIB21(*this);
    }

    virtual void setsubframeBitMap(const std::vector<int> subframeBitMap )
    {
        this->subframeBitMap = subframeBitMap;
    }

    virtual std::vector<int> getsubframeBitMap()
    {
        return subframeBitMap;
    }

    bool isAdjacencyPscchpssch() const {
        return adjacencyPSCCHPSSCH;
    }

    void setAdjacencyPscchpssch(bool adjacencyPscchpssch) {
        adjacencyPSCCHPSSCH = adjacencyPscchpssch;
    }

    int getSlOffsetIndicator() const {
        return SlOffsetIndicator;
    }

    void setSlOffsetIndicator(int slOffsetIndicator) {
        SlOffsetIndicator = slOffsetIndicator;
    }

    int getStartRbSubchannel() const {
        return startRBSubchannel;
    }

    void setStartRbSubchannel(int startRbSubchannel) {
        startRBSubchannel = startRbSubchannel;
    }

    int getNumSubchannel() const {
        return numSubchannel;
    }

    void setNumSubchannel(int numSubchannel) {
        this->numSubchannel = numSubchannel;
    }

    int getSizeSubchannel() const {
        return sizeSubchannel;
    }

    void setSizeSubchannel(int sizeSubchannel) {
        this->sizeSubchannel = sizeSubchannel;
    }
};

#endif



