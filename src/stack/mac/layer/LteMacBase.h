//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#ifndef _LTE_LTEMACBASE_H_
#define _LTE_LTEMACBASE_H_

#include "common/LteCommon.h"
using namespace omnetpp;

class LteHarqBufferTx;
class LteHarqBufferRx;
class LteBinder;
class FlowControlInfo;
class LteMacBuffer;

/**
 * Map associating a nodeId with the corresponding TX H-ARQ buffer.
 * Used in eNB, where there is more than one TX H-ARQ buffer.
 */
typedef std::map<MacNodeId, LteHarqBufferTx *> HarqTxBuffers;

/**
 * Map associating a nodeId with the corresponding RX H-ARQ buffer.
 * Used in eNB, where there is more than one RX H-ARQ buffer.
 */
typedef std::map<MacNodeId, LteHarqBufferRx *> HarqRxBuffers;

/*
 * MultiMap associating a LCG group with all connection belonging to it and
 * corresponding virtual buffer pointer
 */
typedef std::pair<MacCid, LteMacBuffer*> CidBufferPair;
typedef std::pair<LteTrafficClass, CidBufferPair> LcgPair;
typedef std::multimap<LteTrafficClass, CidBufferPair> LcgMap;

/**
 * @class LteMacBase
 * @brief MAC Layer
 *
 * This is the MAC layer of LTE Stack:
 * it performs buffering/sending packets.
 *
 * On each TTI, the handleSelfMessage() is called
 * to perform scheduling and other tasks
 */
class SIMULTE_API LteMacBase : public omnetpp::cSimpleModule
{
	friend class LteHarqBufferTx;
	friend class LteHarqBufferRx;
	friend class LteHarqBufferTxD2D;
	friend class LteHarqBufferRxD2D;

public:

	unsigned int totalOverflowedBytes_;
	::omnetpp::simsignal_t macBufferOverflowDl_;
	::omnetpp::simsignal_t macBufferOverflowUl_;
	::omnetpp::simsignal_t macBufferOverflowD2D_;
	::omnetpp::simsignal_t receivedPacketFromUpperLayer;
	::omnetpp::simsignal_t receivedPacketFromLowerLayer;
	::omnetpp::simsignal_t sentPacketToUpperLayer;
	::omnetpp::simsignal_t sentPacketToLowerLayer;
	::omnetpp::simsignal_t measuredItbs_;

	/*
	 * Data Structures
	 */
	 LteBinder *binder_;

	 /*
	  * Gates
	  */
	 ::omnetpp::cGate* up_[2];     /// RLC <--> MAC
	 ::omnetpp::cGate* down_[2];   /// MAC <--> PHY
	 cGate* control_OUT;
	 cGate* control_IN;
	 /*
	  * MAC MIB Params
	  */
	 bool muMimo_;

	 int harqProcesses_;

	 /// TTI self message
	 ::omnetpp::cMessage* ttiTick_;

	 /// MacNodeId
	 MacNodeId nodeId_;

	 /// MacCellId
	 MacCellId cellId_;

	 /// Mac Buffers maximum queue size
	 int queueSize_;

	 /// Mac Sdu Real Buffers
	 LteMacBuffers mbuf_;

	 /// Mac Sdu Virtual Buffers
	 LteMacBufferMap macBuffers_;

	 /// List of pdus finalized for each user on each codeword
	 MacPduList macPduList_;

	 /// Harq Tx Buffers
	 HarqTxBuffers harqTxBuffers_;

	 /// Harq Rx Buffers
	 HarqRxBuffers harqRxBuffers_;

	 /* Connection Descriptors
	  * Holds flow related infos
	  */
	 std::map<MacCid, FlowControlInfo> connDesc_;

	 /* Incoming Connection Descriptors:
	  * a connection is stored at the first MAC SDU delivered to the RLC
	  */
	 std::map<MacCid, FlowControlInfo> connDescIn_;

	 /* LCG to CID and buffers map - used for supporting LCG - based scheduler operations
	  * TODO : delete/update entries on hand-over
	  */
	 bool ipBased;
	 int retrievedPacketId;
	 int retrievedCAMId;
	 LcgMap lcgMap_;
	 // Node Type;
	 LteNodeType nodeType_;

	 // record the last TTI that HARQ processes for a given UE have been aborted (useful for D2D switching)
	 std::map<MacNodeId, ::omnetpp::simtime_t> resetHarq_;

	 // statistics in visualization
	 bool statDisplay_;
	 uint64_t nrFromUpper_;
	 uint64_t nrFromLower_;
	 uint64_t nrToUpper_;
	 uint64_t nrToLower_;

public:

	 /**
	  * Initializes MAC Buffers
	  */
	 LteMacBase();

	 /**
	  * Deletes MAC Buffers
	  */
	 virtual ~LteMacBase();

	 /**
	  * deleteQueues() must be called on handover
	  * to delete queues for a given user
	  *
	  * @param nodeId Id of the node whose queues are deleted
	  */
	 virtual void deleteQueues(MacNodeId nodeId);

	 //* public utility function - drops ownership of an object
	 void dropObj(cOwnedObject* obj)
	 {
		 drop(obj);
	 }

	 //* public utility function - takes ownership of an object
	 void takeObj(cOwnedObject* obj)
	 {
		 take(obj);
	 }

	 /*
	  * Getters
	  */

	 MacNodeId getMacNodeId()
	 {
		 return nodeId_;
	 }
	 MacCellId getMacCellId()
	 {
		 return cellId_;
	 }

	 // Returns the virtual buffers
	 LteMacBufferMap* getMacBuffers()
	 {
		 return &macBuffers_;
	 }

	 // Returns Traffic Class to cid mapping
	 LcgMap& getLcgMap()
	 {
		 return lcgMap_;
	 }

	 // Returns connection descriptors
	 std::map<MacCid, FlowControlInfo>& getConnDesc()
	 {
		 return connDesc_;
	 }

	 // Returns the harq tx buffers
	 HarqTxBuffers* getHarqTxBuffers()
	 {
		 return &harqTxBuffers_;
	 }

	 // Returns the harq tx buffers
	 HarqRxBuffers* getHarqRxBuffers()
	 {
		 return &harqRxBuffers_;
	 }

	 // Returns number of Harq Processes
	 unsigned int harqProcesses() const
	 {
		 return harqProcesses_;
	 }

	 // Returns the MU-MIMO enabled flag
	 bool muMimo() const
	 {
		 return muMimo_;
	 }

	 LteNodeType getNodeType()
	 {
		 return nodeType_;
	 }

	 void emitItbs( unsigned int iTbs )
	 {
		 emit( measuredItbs_ , iTbs );
	 }

	 virtual bool isD2DCapable()
	 {
		 return false;
	 }

	 // check whether HARQ processes have been aborted during this TTI
	 bool isHarqReset(MacNodeId srcId)
	 {
		 if (resetHarq_.find(srcId) != resetHarq_.end())
		 {
			 if (resetHarq_[srcId] == NOW)
				 return true;
		 }
		 return false;
	 }

	 void unregisterHarqBufferRx(MacNodeId nodeId);

	 // visualization
	 void refreshDisplay() const override;

public:

	 virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }

	 /**
	  * Grabs NED parameters, initializes gates
	  * and the TTI self message
	  */
	 virtual void initialize(int stage) override;

	 /**
	  * Analyze gate of incoming packet
	  * and call proper handler
	  */
	 virtual void handleMessage(::omnetpp::cMessage *msg) override;


	 /**
	  * Statistics recording
	  */
	 virtual void finish() override;

	 /**
	  * Deleting the module
	  *
	  * Method is overridden in order to cancel the periodic TTI self-message,
	  * afterwards the deleteModule method of cSimpleModule is called.
	  */
	 virtual void deleteModule() override;

	 /**
	  * Main loop of the Mac level, calls the scheduler
	  * and every other function every TTI : must be reimplemented
	  * by derivate classes
	  */
	 virtual void handleSelfMessage() = 0;

	 /**
	  * sendLowerPackets() is used
	  * to send packets to lower layer
	  *
	  * @param pkt Packet to send
	  */
	 void sendLowerPackets(omnetpp::cPacket* pkt);

	 /**
	  * sendUpperPackets() is used
	  * to send packets to upper layer
	  *
	  * @param pkt Packet to send
	  */
	 void sendUpperPackets(omnetpp::cPacket* pkt);

	 /*
	  * Functions to be redefined by derivated classes
	  */

	 virtual void macPduMake(MacCid cid = 0) = 0;
	 virtual void macPduUnmake(omnetpp::cPacket* pkt) = 0;

	 /**
	  * bufferizePacket() is called every time a packet is
	  * received from the upper layer
	  */
	 virtual bool bufferizePacket(omnetpp::cPacket* pkt);

	 /**
	  * handleUpperMessage() is called every time a packet is
	  * received from the upper layer
	  */
	 virtual void handleUpperMessage(omnetpp::cPacket* pkt)
	 {
		 bufferizePacket(pkt);
	 }

	 /**
	  * macHandleFeedbackPkt is called every time a feedback pkt arrives on MAC
	  */
	 virtual void macHandleFeedbackPkt(omnetpp::cPacket* pkt)
	 {
	 }

	 /*
	  * Receives and handles scheduling grants - implemented in LteMacUe
	  */
	 virtual void macHandleGrant(omnetpp::cPacket* pkt)
	 {
	 }

	 /*
	  * Receives and handles RAC requests (eNodeB implementation)  and responses (LteMacUe implementation)
	  */
	 virtual void macHandleRac(omnetpp::cPacket* pkt)
	 {
	 }

	 /*
	  * Update UserTxParam stored in every lteMacPdu when an rtx change this information
	  */
	 virtual void updateUserTxParam(omnetpp::cPacket* pkt)=0;

	 /// Upper Layer Handler
	 void fromRlc(omnetpp::cPacket *pkt);

	 /// Lower Layer Handler
	 virtual void fromPhy(omnetpp::cPacket *pkt);

	 //Non-IP related
	 void setIpBased(bool ip)
	 {
		 ip = true;
	 }
	 bool getIpBased()
	 {
		 return ipBased;
	 }

	 void setPacketId(int pid)
	 {
		 retrievedPacketId=pid;
	 }
	 int getPacketId()
	 {
		 return retrievedPacketId;
	 }

	 void setCAMId(int camid)
	 {
		 retrievedCAMId=camid;
	 }
	 int getCAMId()
	 {
		 return retrievedCAMId;
	 }
};

#endif
