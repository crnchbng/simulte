//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#ifndef _LTE_LTEPDCPRRCUED2D_H_
#define _LTE_LTEPDCPRRCUED2D_H_

#include <omnetpp.h>
#include "stack/pdcp_rrc/layer/LtePdcpRrc.h"

/**
 * @class LtePdcp
 * @brief PDCP Layer
 *
 * This is the PDCP/RRC layer of LTE Stack (with D2D support).
 *
 */
class LtePdcpRrcUeD2D : public LtePdcpRrcUe
{
	// initialization flag for each D2D peer
	// it is set to true when the first IP datagram for that peer reaches the PDCP layer

	bool dataArrival;
	int retrievedPktId;
	int retrievedCAMId;
	std::map<const char*, bool> d2dPeeringInit_;
	unsigned int headerLength;
	std::string portName;
	omnetpp::cGate* gate;
	LogicalCid mylcid;
	LtePdcpEntity* entity;
protected:
	virtual void initialize(int stage);

	virtual void handleMessage(cMessage *msg);

	void handleControlInfo(cPacket* upPkt, inet::Ptr<FlowControlInfo> lteInfo)
	{
		//delete lteInfo;
	}
	void handleControlInfo(cPacket* upPkt, inet::Ptr<FlowControlInfoNonIp> lteInfo)
	{
		//delete lteInfo;
	}

	virtual MacNodeId getDestId(inet::Ptr<FlowControlInfo> lteInfo);
	MacNodeId getDestId(inet::Ptr<FlowControlInfoNonIp> lteInfo)
	{
		// UE is subject to handovers: master may change
		return binder_->getNextHop(nodeId_);
	}

	Direction getDirection(MacNodeId destId)
	{
		if (binder_->getD2DCapability(nodeId_, destId) && binder_->getD2DMode(nodeId_, destId) == DM)
			return D2D;
		return UL;
	}
	Direction getDirection()
	{
		return D2D_MULTI;
	}

	/**
	 * handler for data port
	 * @param pkt incoming packet
	 */
	virtual void fromDataPort(cPacket *pkt);

	// handler for mode switch signal
	void pdcpHandleD2DModeSwitch(MacNodeId peerId, LteD2DMode newMode);

	virtual void setDataArrivalStatus(bool);
	virtual void finish();

public:
	virtual bool getDataArrivalStatus(){
		return dataArrival;
	}
};

#endif
