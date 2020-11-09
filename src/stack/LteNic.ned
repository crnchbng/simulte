// 
//                           SimuLTE
// 
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself, 
// and cannot be removed from it.
// 


package lte.stack;

import inet.linklayer.contract.IWirelessNic;
import lte.stack.phy.LtePhy;
import lte.stack.mac.LteMac;
import lte.stack.pdcp_rrc.LtePdcpRrc;
import lte.stack.phy.feedback.LteDlFeedbackGenerator;
import lte.stack.rlc.LteRlc;
import lte.corenetwork.lteip.IP2lte;
import lte.x2.LteX2Manager;
import lte.stack.compManager.LteCompManager;
import lte.stack.d2dModeSelection.D2DModeSelection;
import lte.stack.handoverManager.LteHandoverManager;
import lte.control.ControlPlane;
import lte.stack.phy.ChannelModel.LteChannelModelInterface;
import lte.stack.phy.resources.SidelinkResourceAllocation;
import lte.stack.mac.configuration.SidelinkConfiguration;
import lte.corenetwork.multiplextraffic.TrafficMux;

// 
// Interface for the LTE Stack.
//
moduleinterface ILteNic extends IWirelessNic
{
        string nodeType;
        //bool d2dCapable;            // inherit the value from the parent module
    gates:
        inout EUTRAN_RRC_Sap;   // Control of RRC Layer
        inout x2[] @loose;     // optional x2 manager
        input control_IN @loose;
        
        
}

// 
// Base module for the LTE Stack.
//
// TODO: implement IWirelessNic
module LteNicBase like ILteNic
{
    parameters:
        @display("i=block/ifcard;bgb=808.19196,583.29596;bgl=3");
        string interfaceTableModule;
        string routingTableModule;
        string LtePdcpRrcType;      // One of: "LtePdcpRrcUe", "LtePdcpRrcEnb", "LtePdcpRrcRelayUe", "LtePdcpRrcRelayEnb"
        string LteMacType;          // One of: "LteMacUe", "LteMacEnb", "LteMacRelayUe", "LteMacRelayEnb"
        string LtePhyType;
        string LteRrcType;
        string nodeType;
        bool ipBased;
        string LteChannelModelType = default("LteRealisticChannelModel");
        bool d2dCapable;            // inherit the value from the parent module
        
    gates:
        //#
        //# Gates connecting UE/eNB and LTE Stack
        //#
        //# Control Ports
        inout EUTRAN_RRC_Sap;   // Control of RRC Layer
        
        //#IPtraffic
        input upperLayerIn @loose;
        output upperLayerOut @loose;
        input upperLayerNonIpIn @loose;
        output upperLayerNonIpOut @loose;
        
        input radioIn @loose;  // to receive messages sent using sendDirect()
        inout x2[] @loose;     // optional x2 manager
        input control_IN @loose; // sendDirect() on control plane
    submodules:
        // bridge between lte stack and network layer
        control: <LteRrcType> like ControlPlane {
                @display("p=66.304,141.568");
                nodeType = nodeType;
        }
        
        
        ip2lte: IP2lte {
                nodeType = nodeType;
                interfaceTableModule = interfaceTableModule;
                routingTableModule = routingTableModule;
                @display("p=155.90399,167.552");
        }
        // PDCP-RRC Layer
        pdcpRrc: <LtePdcpRrcType> like LtePdcpRrc {
                ipBased = false;
                @display("p=150.528,234.752");
                nodeType = nodeType;
        }
        // RLC Layer
        rlc: LteRlc {
                @display("p=155.90399,327.03998");
                d2dCapable = d2dCapable;
        }
        // MAC Layer
        mac: <LteMacType> like LteMac {
                interfaceTableModule = interfaceTableModule;
                @display("p=155.90399,396.92798");
        }
        // LtePhy submodule
        phy: <LtePhyType> like LtePhy {
                @display("p=150.528,486.52798");
                @class(LtePhyType);
        }
        
        channelModel: <LteChannelModelType> like LteChannelModelInterface {
                @display("p=44.8,389.75998");
        }
        
    connections:
        
        ip2lte.upperLayerOut --> upperLayerOut;
        upperLayerIn --> ip2lte.upperLayerIn;
        ip2lte.stackLte$o --> pdcpRrc.DataPortIpIn;
        ip2lte.stackLte$i <-- pdcpRrc.DataPortIpOut;
        
        pdcpRrc.DataPortNonIpOut --> upperLayerNonIpOut;
        upperLayerNonIpIn --> pdcpRrc.DataPortNonIpIn;
        
        
        
        //#
        //# Internal LTE Stack Connections 
        //# 
        
        EUTRAN_RRC_Sap <--> pdcpRrc.EUTRAN_RRC_Sap;
        
        //# PDCP <-> RLC
        pdcpRrc.UM_Sap <--> rlc.UM_Sap;
        pdcpRrc.AM_Sap <--> rlc.AM_Sap;
        pdcpRrc.TM_Sap <--> rlc.TM_Sap;
        
        //# RLC <-> MAC
        rlc.RLC_to_MAC --> mac.RLC_to_MAC;
        rlc.MAC_to_RLC <-- mac.MAC_to_RLC;
        
        //#
        //# Connections from LTE Stack to radio interface
        //#
        mac.MAC_to_PHY --> phy.upperGateIn;
        mac.PHY_to_MAC <-- phy.upperGateOut;
        
        //# external: lower connection
        radioIn --> phy.radioIn;
        
        //#Control plane
        control.PDCP_control <--> pdcpRrc.control;
        control.TM_control <--> rlc.TM_control;
        control.AM_control <--> rlc.AM_control;
        control.UM_control <--> rlc.UM_control;
        control.PHY_control <--> phy.control;
        control.MAC_control <--> mac.control;
        control_IN --> control.control_IN;
}

//
// User Equipment of LTE stack
//
module LteNicUe extends LteNicBase
{
    parameters:
        LtePdcpRrcType = default("LtePdcpRrcUe");
        LteMacType = default("LteMacUe");
        LtePhyType = default("LtePhyUe");
        d2dCapable = default(false);          // DO NOT CHANGE
        LteRrcType = default("LteRrcUe");
    gates:
        
    submodules:
        // Feedback generator submodule
        dlFbGen: LteDlFeedbackGenerator {
                @display("p=50,50;is=s");
        }
        mode4: SidelinkResourceAllocation {
                @display("p=49.28,236.54399;i=block/cogwheel");
        }
        mode4config: SidelinkConfiguration;
}

//
// D2D-capable User Equipment of LTE stack
//
module LteNicUeD2D extends LteNicUe
{
    parameters:
        LtePdcpRrcType = default("LtePdcpRrcUeD2D");
        LteMacType = default("LteMacUeD2D");
        LtePhyType = default("LtePhyUeD2D");
        LteRrcType = default("LteRrcUe");
        d2dCapable = default(true);             // DO NOT CHANGE
        bool d2dInitialMode = default(false);
        string d2dPeerAddresses = default("");  // list of D2D peer UEs, separated by blank spaces
}

//
// eNodeB of LTE stack
//
module LteNicEnb extends LteNicBase
{
    parameters:
        LtePdcpRrcType = default("LtePdcpRrcEnb");
        LteMacType = default("LteMacEnb");
        LtePhyType = default("LtePhyEnb");
        d2dCapable = default(false);          // DO NOT CHANGE
        LteRrcType = default("LteRrcEnb");
        bool compEnabled = default(false);
        string LteCompManagerType = default("LteCompManagerProportional");
        
    submodules:
        //#
        //# X2 manager
        //#       
        x2Manager: LteX2Manager {
                @display("p=60,227,row");
        }
        
        //#
        //# Modules exploiting X2 interface
        //#
        compManager: <LteCompManagerType> like LteCompManager if compEnabled {
                @display("p=60,315,row");
        }
        handoverManager: LteHandoverManager {
                @display("p=60,142,row");
        }
        
        
        mode3: SidelinkResourceAllocation {
                @display("p=49.28,236.54399;i=block/cogwheel");
        }
        mode3config: SidelinkConfiguration;
        
    connections:
        //# connections between X2 Manager and its users
        compManager.x2ManagerIn <-- x2Manager.dataPort$o++ if compEnabled;
        compManager.x2ManagerOut --> x2Manager.dataPort$i++ if compEnabled;
        handoverManager.x2ManagerIn <-- x2Manager.dataPort$o++;
        handoverManager.x2ManagerOut --> x2Manager.dataPort$i++;
        
        if ( sizeof(x2) > 0 ) {
                //# connections between X2 Manager and GTP (for handover)
                x2$i[0] --> x2Manager.x2Gtp$i;
                x2$o[0] <-- x2Manager.x2Gtp$o;
        }
        //# connections between X2 Manager and the outer world
        for i=1..sizeof(x2)-1 {
                x2$i[i] --> x2Manager.x2$i++;
                x2$o[i] <-- x2Manager.x2$o++;
        }
}

//
// eNodeB of LTE stack with support for D2D-capable UEs
//
module LteNicEnbD2D extends LteNicEnb
{
    parameters:
        LtePdcpRrcType = default("LtePdcpRrcEnbD2D");
        LteMacType = default("LteMacEnbD2D");
        LtePhyType = default("LtePhyEnbD2D");
        LteRrcType = default("LteRrcEnb");
        d2dCapable = default(true);   // DO NOT CHANGE
        string d2dModeSelectionType = default("D2DModeSelectionBase");
        
    submodules:
        d2dModeSelection: <d2dModeSelectionType> like D2DModeSelection {
                @display("p=60,68,row");
        }
}

//
// Relay of LTE stack
//
module LteNicRelay extends LteNicBase
{
    parameters:
        LtePhyType = "LtePhyRelay";
        d2dCapable = false;
        
    submodules:
        // Feedback generator submodule
        dlFbGen: LteDlFeedbackGenerator {
                @display("p=50,50;is=s");
        }
        
        // TODO Feedback generator submodule
        // ulFbGen: LteUlFeedbackGenerator {
        //     @display("p=200,150;is=s");
        // }
}

// Relay of LTE stack
//
module LteNicRsuEnb extends LteNicBase
{
    parameters:
        LtePdcpRrcType = default("LtePdcpRrcEnbD2D");
        LteMacType = default("LteMacEnbD2D");
        LteRrcType = default("LteRrcRsuEnb");
        LtePhyType = "LtePhyRsu";
        d2dCapable = true;
        bool compEnabled = default(false);
        string LteCompManagerType = default("LteCompManagerProportional");
    submodules:
        x2Manager: LteX2Manager {
                @display("p=60,227,row");
        }
        
        //#
        //# Modules exploiting X2 interface
        //#
        compManager: <LteCompManagerType> like LteCompManager if compEnabled {
                @display("p=60,315,row");
        }
        handoverManager: LteHandoverManager {
                @display("p=60,142,row");
        }
        
        
        mode3: SidelinkResourceAllocation {
                @display("p=49.28,236.54399;i=block/cogwheel");
        }
        mode3config: SidelinkConfiguration;
    connections:
        //# connections between X2 Manager and its users
        compManager.x2ManagerIn <-- x2Manager.dataPort$o++ if compEnabled;
        compManager.x2ManagerOut --> x2Manager.dataPort$i++ if compEnabled;
        handoverManager.x2ManagerIn <-- x2Manager.dataPort$o++;
        handoverManager.x2ManagerOut --> x2Manager.dataPort$i++;
        
        if ( sizeof(x2) > 0 ) {
                //# connections between X2 Manager and GTP (for handover)
                x2$i[0] --> x2Manager.x2Gtp$i;
                x2$o[0] <-- x2Manager.x2Gtp$o;
        }
        //# connections between X2 Manager and the outer world
        for i=1..sizeof(x2)-1 {
                x2$i[i] --> x2Manager.x2$i++;
                x2$o[i] <-- x2Manager.x2$o++;
        }
}





