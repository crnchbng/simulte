//IP Based Alert message

#ifndef _LTE_ALERTSENDER_H_
#define _LTE_ALERTSENDER_H_

#include <string.h>
#include <omnetpp.h>
#include "inet/transportlayer/contract/udp/UDPSocket.h"
#include "inet/networklayer/common/L3Address.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "apps/alert/AlertPacket_m.h"

class AlertSender : public cSimpleModule
{
    inet::UDPSocket socket;
    int nextSno_;
    int size_;
    int localPort_;
    int destPort_;
    inet::L3Address destAddress_;
    int pktId;

    simtime_t period_;
    simtime_t stopTime_;
    simsignal_t alertSentMsg_;
    simsignal_t  transmittedPId;
    // ----------------------------

    cMessage *selfSender_;

public:
    ~AlertSender();
    AlertSender();
    void sendAlertPacket();
protected:

    virtual int numInitStages() const { return inet::NUM_INIT_STAGES; }
    void initialize(int stage);
    void handleMessage(cMessage *msg);
};

#endif

