//
//                           SimuLTE
//
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself,
// and cannot be removed from it.
//

#include "stack/pdcp_rrc/layer/LtePdcpRrc.h"
#include "stack/pdcp_rrc/packet/LteRohcPdu_m.h"

#include "inet/networklayer/common/L3Tools.h"
#include "inet/transportlayer/common/L4Tools.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"
#include "inet/transportlayer/tcp_common/TcpHeader.h"

Define_Module(LtePdcpRrcUe);
Define_Module(LtePdcpRrcEnb);
Define_Module(LtePdcpRrcRelayUe);
Define_Module(LtePdcpRrcRelayEnb);

LtePdcpRrcBase::LtePdcpRrcBase()
{
	ht_ = new ConnectionsTable();
	nonIpHt_ = new NonIpConnectionsTable();
	lcid_ = 1;
}

LtePdcpRrcBase::~LtePdcpRrcBase()
{
	delete ht_;
	delete nonIpHt_;

	PdcpEntities::iterator it = entities_.begin();
	for (; it != entities_.end(); ++it)
	{
		delete it->second;
	}
	entities_.clear();
}

void LtePdcpRrcBase::headerCompress(Packet* pkt)
{
	if (isCompressionEnabled())
	{
		auto ipHeader = pkt->removeAtFront<Ipv4Header>();

		int transportProtocol = ipHeader->getProtocolId();
		B transportHeaderCompressedSize = B(0);

		auto rohcHeader = makeShared<LteRohcPdu>();
		rohcHeader->setOrigSizeIpHeader(ipHeader->getHeaderLength());

		if (IP_PROT_TCP == transportProtocol) {
			auto tcpHeader = pkt->removeAtFront<tcp::TcpHeader>();
			rohcHeader->setOrigSizeTransportHeader(tcpHeader->getHeaderLength());
			tcpHeader->setChunkLength(B(1));
			transportHeaderCompressedSize = B(1);
			pkt->insertAtFront(tcpHeader);
		}
		else if (IP_PROT_UDP == transportProtocol) {
			auto udpHeader = pkt->removeAtFront<UdpHeader>();
			rohcHeader->setOrigSizeTransportHeader(inet::UDP_HEADER_LENGTH);
			udpHeader->setChunkLength(B(1));
			transportHeaderCompressedSize = B(1);
			pkt->insertAtFront(udpHeader);
		} else {
			EV_WARN << "LtePdcp : unknown transport header - cannot perform transport header compression";
			rohcHeader->setOrigSizeTransportHeader(B(0));
		}

		ipHeader->setChunkLength(B(1));
		pkt->insertAtFront(ipHeader);

		rohcHeader->setChunkLength(headerCompressedSize_-transportHeaderCompressedSize-B(1));
		pkt->insertAtFront(rohcHeader);

		EV << "LtePdcp : Header compression performed\n";
	}
}

void LtePdcpRrcBase::headerDecompress(Packet* pkt)
{
	if (isCompressionEnabled())
	{
		pkt->trim();
		auto rohcHeader = pkt->removeAtFront<LteRohcPdu>();
		auto ipHeader = pkt->removeAtFront<Ipv4Header>();
		int transportProtocol = ipHeader->getProtocolId();

		if (IP_PROT_TCP == transportProtocol) {
			auto tcpHeader = pkt->removeAtFront<tcp::TcpHeader>();
			tcpHeader->setChunkLength(rohcHeader->getOrigSizeTransportHeader());
			pkt->insertAtFront(tcpHeader);
		}
		else if (IP_PROT_UDP == transportProtocol) {
			auto udpHeader = pkt->removeAtFront<UdpHeader>();
			udpHeader->setChunkLength(rohcHeader->getOrigSizeTransportHeader());
			pkt->insertAtFront(udpHeader);
		} else {
			EV_WARN << "LtePdcp : unknown transport header - cannot perform transport header decompression";
		}

		ipHeader->setChunkLength(rohcHeader->getOrigSizeIpHeader());
		pkt->insertAtFront(ipHeader);

		EV << "LtePdcp : Header decompression performed\n";
	}
}


/*
 * TODO
 * Osservando le porte tira fuori:
 * lteInfo->setApplication();
 * lteInfo->setDirection();
 * lteInfo->setTraffic();
 * lteInfo->setRlcType();
 */
void LtePdcpRrcBase::setTrafficInformation(cPacket* pkt,
		inet::Ptr<FlowControlInfo> lteInfo)
{
	if ((strcmp(pkt->getName(), "VoIP")) == 0)
	{
		lteInfo->setApplication(VOIP);
		lteInfo->setTraffic(CONVERSATIONAL);
		lteInfo->setRlcType((int) par("conversationalRlc"));
	}
	else if ((strcmp(pkt->getName(), "gaming")) == 0)
	{
		lteInfo->setApplication(GAMING);
		lteInfo->setTraffic(INTERACTIVE);
		lteInfo->setRlcType((int) par("interactiveRlc"));
	}
	else if ((strcmp(pkt->getName(), "VoDPacket") == 0)
			|| (strcmp(pkt->getName(), "VoDFinishPacket") == 0))
	{
		lteInfo->setApplication(VOD);
		lteInfo->setTraffic(STREAMING);
		lteInfo->setRlcType((int) par("streamingRlc"));
	}
	else
	{
		lteInfo->setApplication(CBR);
		lteInfo->setTraffic(BACKGROUND);
		lteInfo->setRlcType((int) par("backgroundRlc"));
	}

	lteInfo->setDirection(getDirection());
}

void LtePdcpRrcBase::setTrafficInformation(cPacket* pkt, inet::Ptr<FlowControlInfoNonIp>  nonIpInfo)
{
	EV<<"LtePdcpRrcBase::setTrafficInformation: "<<endl;

	nonIpInfo->setApplication(GEONET);
	nonIpInfo->setTraffic(CAM);
	nonIpInfo->setRlcType((int) par("backgroundRlc"));
	nonIpInfo->setDirection(getDirection());
}

/*
 * Upper Layer handlers
 */

void LtePdcpRrcBase::fromDataPort(cPacket *pktAux)
{
	EV<<"LtePdcpRrcBase::fromDataPort"<<ipBased_<<endl;
	emit(receivedPacketFromUpperLayer, pktAux);
	auto pkt = check_and_cast<inet::Packet *> (pktAux);
	auto lteInfo = pkt->getTagForUpdate<FlowControlInfo>();
	LogicalCid mylcid;
	// get the PDCP entity for this LCID
	LtePdcpEntity* entity;

	setTrafficInformation(pkt, lteInfo);

	EV<<"LtePdcpRrcBase::fromDataPort ipBased: "<<ipBased_<<endl;
	if (ipBased_)
		// Control Informations
	{auto lteInfo = pkt->getTagForUpdate<FlowControlInfo>();


	lteInfo->setDestId(getDestId(lteInfo));
	headerCompress(pkt); // header compression

	// Cid Request
	EV << "LteRrc : Received CID request for Traffic [ " << "Source: "
			<< Ipv4Address(lteInfo->getSrcAddr()) << "@" << lteInfo->getSrcPort()
			<< " Destination: " << Ipv4Address(lteInfo->getDstAddr()) << "@"
			<< lteInfo->getDstPort() << " ]\n";

	// TODO: Since IP addresses can change when we add and remove nodes, maybe node IDs should be used instead of them
	LogicalCid mylcid;
	if ((mylcid = ht_->find_entry(lteInfo->getSrcAddr(), lteInfo->getDstAddr(),
			lteInfo->getSrcPort(), lteInfo->getDstPort())) == 0xFFFF)
	{
		// LCID not found
		mylcid = lcid_++;

		EV << "LteRrc : Connection not found, new CID created with LCID " << mylcid << "\n";

		ht_->create_entry(lteInfo->getSrcAddr(), lteInfo->getDstAddr(),
				lteInfo->getSrcPort(), lteInfo->getDstPort(), mylcid);
	}
	entity= getEntity(mylcid);

	// get the sequence number for this PDCP SDU.
	// Note that the numbering depends on the entity the packet is associated to.
	unsigned int sno = entity->nextSequenceNumber();

	// set sequence number
	lteInfo->setSequenceNumber(sno);
	setDataArrivalStatus(true);
	EV << "LteRrc : Assigned Lcid: " << mylcid << "\n";
	EV << "LteRrc : Assigned Node ID: " << nodeId_ << "\n";
	}
	else{
		auto nonIpInfo = pkt->getTagForUpdate<FlowControlInfoNonIp>();

		nonIpInfo->setDestId(getDestId(nonIpInfo));

		// Cid Request
		EV << "LteRrc : Received CID request for Traffic [ " << "Source: "
				<< nonIpInfo->getSrcAddr() << " Destination: " << nonIpInfo->getDstAddr() << " ]\n";

		if ((mylcid = nonIpHt_->find_entry(nonIpInfo->getSrcAddr(), nonIpInfo->getDstAddr())) == 0xFFFF)
		{
			// LCID not found
			mylcid = lcid_++;

			EV << "LteRrc : Connection not found, new CID created with LCID " << mylcid << "\n";

			nonIpHt_->create_entry(nonIpInfo->getSrcAddr(), nonIpInfo->getDstAddr(), mylcid);

		}
		entity= getEntity(mylcid);

		// get the sequence number for this PDCP SDU.
		// Note that the numbering depends on the entity the packet is associated to.
		unsigned int sno = entity->nextSequenceNumber();

		// set sequence number
		nonIpInfo->setSequenceNumber(sno);
	}
	EV << "LteRrc : Assigned Lcid: " << mylcid << "\n";
	EV << "LteRrc : Assigned Node ID: " << nodeId_ << "\n";

	// NOTE setLcid and setSourceId have been anticipated for using in "ctrlInfoToMacCid" function
	lteInfo->setLcid(mylcid);
	lteInfo->setSourceId(nodeId_);
	lteInfo->setDestId(getDestId(lteInfo));

	// PDCP Packet creation
	auto pdcpPkt  = makeShared<LtePdcpPdu>();
	//LtePdcpPdu* pdcpPkt = new LtePdcpPdu("LtePdcpPdu");
	unsigned int headerLength;
	std::string portName;
	omnetpp::cGate* gate;

	switch(lteInfo->getRlcType()){
	case UM:
		headerLength = PDCP_HEADER_UM;
		portName = "UM_Sap$o";
		gate = umSap_[OUT_GATE];
		break;
	case AM:
		headerLength = PDCP_HEADER_AM;
		portName = "AM_Sap$o";
		gate = amSap_[OUT_GATE];
		break;
	case TM:
		portName = "TM_Sap$o";
		gate = tmSap_[OUT_GATE];
		headerLength = 1;
		break;
	default:
		throw cRuntimeError("LtePdcpRrcBase::fromDataport(): invalid RlcType %d", lteInfo->getRlcType());
		portName = "undefined";
		gate = nullptr;
		headerLength = 1;
	}
	pdcpPkt->setChunkLength(B(headerLength));
	pkt->trim();
	pkt->insertAtFront(pdcpPkt);

	EV << "LtePdcp : Preparing to send "
			<< lteTrafficClassToA((LteTrafficClass) lteInfo->getTraffic())
			<< " traffic\n";
	EV << "LtePdcp : Packet size " << pkt->getByteLength() << " Bytes\n";

	lteInfo->setSourceId(nodeId_);
	lteInfo->setLcid(mylcid);

	EV << "LtePdcp : Sending packet " << pkt->getName() << " on port "
			<< portName.c_str() << std::endl;

	pkt->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&LteProtocol::pdcp);

	// Send message
	send(pkt, gate);
	emit(sentPacketToLowerLayer, pkt);
}


void LtePdcpRrcBase::setDataArrivalStatus(bool dataArrival)
{
	this->dataArrival = dataArrival;
}

bool LtePdcpRrcBase::getDataArrivalStatus(){
	return dataArrival;
}


void LtePdcpRrcBase::fromEutranRrcSap(cPacket *pkt)
{
	// TODO For now use LCID 1000 for Control Traffic coming from RRC
	FlowControlInfo* lteInfo = new FlowControlInfo();
	lteInfo->setSourceId(nodeId_);
	lteInfo->setLcid(1000);
	lteInfo->setRlcType(TM);
	pkt->setControlInfo(lteInfo);
	EV << "LteRrc : Sending packet " << pkt->getName() << " on port TM_Sap$o\n";
	send(pkt, tmSap_[OUT_GATE]);
}

/*
 * Lower layer handlers
 */

void LtePdcpRrcBase::toDataPort(cPacket *pktAux)
{

	auto pkt = check_and_cast<Packet *>(pktAux);
	    emit(receivedPacketFromLowerLayer, pkt);

	    auto pdcpPkt = pkt->popAtFront<LtePdcpPdu>();

	if (ipBased_)
	{
		 auto lteInfo = pkt->removeTag<FlowControlInfo>();
		EV << "LtePdcp : Received packet with CID " << lteInfo->getLcid() << "\n";
		EV << "LtePdcp : Packet size " << pkt->getByteLength() << " Bytes\n";

		headerDecompress(pkt);
		handleControlInfo(pkt, lteInfo);

		pkt->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ipv4);

		EV << "LtePdcp : Sending packet " << pkt->getName()
			    						   << " on port DataPort$o" << std::endl;
		// Send message
		send(pkt, dataPort_[OUT_GATE]);
		emit(sentPacketToUpperLayer, pkt);


	}
	else
	{
		 auto lteInfo = pkt->removeTag<FlowControlInfoNonIp>();
		EV << "LtePdcp : Received packet with CID " << lteInfo->getLcid() << "\n";
		EV << "LtePdcp : Packet size " << pkt->getByteLength() << " Bytes\n";

		headerDecompress(pkt);
		handleControlInfo(pkt, lteInfo);

		pkt->addTagIfAbsent<PacketProtocolTag>()->setProtocol(&Protocol::ipv4);

		EV << "LtePdcp : Sending packet " << pkt->getName()
					    						   << " on port DataPort$o" << std::endl;
		// Send message
		send(pkt, dataPort_[OUT_GATE]);
		emit(sentPacketToUpperLayer, pkt);
	}


	/*



	emit(receivedPacketFromLowerLayer, pkt);
	LtePdcpPdu* pdcpPkt = check_and_cast<LtePdcpPdu*>(pkt);
	cPacket* upPkt;

	if (ipBased_)
	{
		FlowControlInfo* lteInfo = check_and_cast<FlowControlInfo*>(
				pdcpPkt->getTag<FlowControlInfo>());

		EV << "LtePdcp : Received packet with CID " << lteInfo->getLcid() << "\n";
		EV << "LtePdcp : Packet size " << pdcpPkt->getChunkLength() << " Bytes\n";

		upPkt = pdcpPkt->decapsulate(); // Decapsulate packet
		delete pdcpPkt;

		headerDecompress(upPkt, lteInfo->getHeaderSize()); // Decompress packet header
		handleControlInfo(upPkt, lteInfo);
		EV << "LtePdcp : Sending IP packet " << upPkt->getName()
                    		   << " on port DataPort$o\n";
		// Send message
		send(upPkt, DataPortIpOut);
		emit(sentPacketToUpperLayer, upPkt);
	}
	else
	{
		FlowControlInfoNonIp* lteInfo = check_and_cast<FlowControlInfoNonIp*>(
				pdcpPkt->removeControlInfo());
		EV << "LtePdcp : Received packet with CID " << lteInfo->getLcid() << "\n";
		EV << "LtePdcp : Packet size " << pdcpPkt->getByteLength() << " Bytes\n";

		upPkt = pdcpPkt->decapsulate(); // Decapsulate packet
		delete pdcpPkt;
		upPkt->setControlInfo(lteInfo);
		EV << "LtePdcp : Sending Non IP packet " << upPkt->getName()
                        		   << " on port DataPort$o\n";
		// Send message
		send(upPkt, DataPortNonIpOut);
		emit(sentPacketToUpperLayer, upPkt);
	}
	 */

}

void LtePdcpRrcBase::toEutranRrcSap(cPacket *pkt)
{
	cPacket* upPkt = pkt->decapsulate();
	delete pkt;

	EV << "LteRrc : Sending packet " << upPkt->getName()
            						   << " on port EUTRAN_RRC_Sap$o\n";
	send(upPkt, eutranRrcSap_[OUT_GATE]);
}

/*
 * Main functions
 */

void LtePdcpRrcBase::initialize(int stage)
{
	if (stage == inet::INITSTAGE_LOCAL)
	{
		dataPort_[IN_GATE] = gate("DataPort$i");
		dataPort_[OUT_GATE] = gate("DataPort$o");
		DataPortIpIn = gate("DataPortIpIn");
		DataPortIpOut = gate("DataPortIpOut");
		DataPortNonIpIn = gate("DataPortNonIpIn");
		DataPortNonIpOut = gate("DataPortNonIpOut");
		eutranRrcSap_[IN_GATE] = gate("EUTRAN_RRC_Sap$i");
		eutranRrcSap_[OUT_GATE] = gate("EUTRAN_RRC_Sap$o");
		tmSap_[IN_GATE] = gate("TM_Sap$i");
		tmSap_[OUT_GATE] = gate("TM_Sap$o");
		umSap_[IN_GATE] = gate("UM_Sap$i");
		umSap_[OUT_GATE] = gate("UM_Sap$o");
		amSap_[IN_GATE] = gate("AM_Sap$i");
		amSap_[OUT_GATE] = gate("AM_Sap$o");

		binder_ = getBinder();
		headerCompressedSize_ = B(par("headerCompressedSize"));
		if(headerCompressedSize_ != LTE_PDCP_HEADER_COMPRESSION_DISABLED &&
				headerCompressedSize_ < MIN_COMPRESSED_HEADER_SIZE)
		{
			throw cRuntimeError("Size of compressed header must not be less than %i", MIN_COMPRESSED_HEADER_SIZE.get());
		}

		nodeId_ = getAncestorPar("macNodeId");

		// statistics
		receivedPacketFromUpperLayer = registerSignal("receivedPacketFromUpperLayer");
		receivedPacketFromLowerLayer = registerSignal("receivedPacketFromLowerLayer");
		sentPacketToUpperLayer = registerSignal("sentPacketToUpperLayer");
		sentPacketToLowerLayer = registerSignal("sentPacketToLowerLayer");

		// TODO WATCH_MAP(gatemap_);
		WATCH(headerCompressedSize_);
		WATCH(nodeId_);
		WATCH(lcid_);
	}
}
void LtePdcpRrcBase::setNodeType(std::string s)
{
	nodeType_ = aToNodeType(s);
	EV << "Node type: " << s << " -> " << nodeType_ << endl;
}
void LtePdcpRrcBase::handleMessage(cMessage* msg)
{
	cPacket* pkt = check_and_cast<cPacket *>(msg);
	EV << "LtePdcpRrcBase::handleMessage LtePdcp : Received packet " << pkt->getName() << " from port "
			<< pkt->getArrivalGate()->getName() << endl;

	cGate* incoming = pkt->getArrivalGate();
	if (incoming == DataPortIpIn || incoming == DataPortNonIpIn)
	{
		EV<<"Incoming: DataPortIn"<<endl;
		fromDataPort(pkt);
	}
	else if (incoming == eutranRrcSap_[IN_GATE])
	{
		fromEutranRrcSap(pkt);
	}
	else if (incoming == tmSap_[IN_GATE])
	{
		toEutranRrcSap(pkt);
	}
	else
	{
		EV<<"Incoming: else"<<endl;
		toDataPort(pkt);
	}
	return;
}

LtePdcpEntity* LtePdcpRrcBase::getEntity(LogicalCid lcid)
{
	// Find entity for this LCID
	PdcpEntities::iterator it = entities_.find(lcid);
	if (it == entities_.end())
	{
		// Not found: create
		LtePdcpEntity* ent = new LtePdcpEntity();
		entities_[lcid] = ent;    // Add to entities map

		EV << "LtePdcpRrcBase::getEntity - Added new PdcpEntity for Lcid: " << lcid << "\n";

		return ent;
	}
	else
	{
		// Found
		EV << "LtePdcpRrcBase::getEntity - Using old PdcpEntity for Lcid: " << lcid << "\n";

		return it->second;
	}

}

void LtePdcpRrcBase::finish()
{
	// TODO make-finish
}

void LtePdcpRrcEnb::initialize(int stage)
{
	LtePdcpRrcBase::initialize(stage);
	if (stage == inet::INITSTAGE_LOCAL)
		nodeId_ = getAncestorPar("macNodeId");
}

void LtePdcpRrcUe::initialize(int stage)
{
	LtePdcpRrcBase::initialize(stage);
	if (stage == inet::INITSTAGE_NETWORK_LAYER)
	{
		nodeId_ = getAncestorPar("macNodeId");
	}
}

