// 
//                           SimuLTE
// 
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself, 
// and cannot be removed from it.
// 


package lte.stack.phy;

// 
// Interface for the LtePhy module of PHY Layer
//
moduleinterface LtePhy {
    parameters:
        @display("i=block/wrxtx");
        
    gates:
        input upperGateIn;
        output upperGateOut;
        input radioIn;
        inout control;
}

// 
// Base LtePhy module of PHY Layer
//
simple LtePhyBase like LtePhy {
    parameters:
        @display("i=block/wrxtx");
        double ueTxPower =default(26);
        double eNodeBTxPower =default(46);
        double relayTxPower =default(20);
        double microTxPower =default(30);
        string txDirection = default("OMNI");
        double txAngle = default(0);       
        
        bool dynamicCellAssociation = default(false);
        
        // switch for handover messages handling on UEs
        bool enableHandover = default(false);
        double handoverLatency @unit(s) = default(0.05s);
        
        // TODO move to LtePhyUeD2D module
        bool enableMulticastD2DRangeCheck = default(false); //and resource blocks
        double multicastD2DRange @unit(m) = default(1000m);
        
        
        
    gates:
        input upperGateIn;       // from upper layer
        output upperGateOut;    // to upper layer
        input radioIn;           // gate to receive message via sendDirect
        inout control;
}

// 
// User Equipment LtePhy module of PHY Layer
//
simple LtePhyUe extends LtePhyBase {
    parameters:
        @class("LtePhyUe");
         @signal[servingCell];
         @statistic[servingCell](title="ID of the serving eNodeB for the UE"; unit=""; source="servingCell"; record=vector);
         @signal[averageCqiDl];
         @statistic[averageCqiDl](title="Average Cqi reported in DL"; unit="cqi"; source="averageCqiDl"; record=mean,vector);
         @signal[averageCqiUl];
         @statistic[averageCqiUl](title="Average Cqi reported in UL"; unit="cqi"; source="averageCqiUl"; record=mean,vector);
        @signal[numberReceivedPackets];
		@statistic[numberReceivedPackets](title="NUmber of CAMs received"; source="numberReceivedPackets"; record=vector,stats);
		@signal[numberTransmittedPackets];
		@statistic[numberTransmittedPackets](title="NUmber of CAMs transmitted"; source="numberTransmittedPackets"; record=vector,stats);
		@signal[numberAlertTransmittedPackets];
		@statistic[numberAlertTransmittedPackets](title="NUmber of Alert Messages transmitted"; source="numberAlertTransmittedPackets"; record=vector,stats);
        @signal[AlertTransmittedId];
		@statistic[AlertTransmittedId](title="Packet Id of successfully transmitted Alert packet"; source="AlertTransmittedId"; record=vector,stats);
		 @signal[CAMTransmittedId];
		@statistic[CAMTransmittedId](title="Packet Id of successfully transmitted CAM packet"; source="CAMTransmittedId"; record=vector,stats);
}

// 
// D2D-capable User Equipment LtePhy module of PHY Layer
//
simple LtePhyUeD2D extends LtePhyUe {
    parameters:
        @class("LtePhyUeD2D");
        double d2dTxPower =default(26);
        bool d2dMulticastCaptureEffect = default(true);
        string d2dMulticastCaptureEffectFactor = default("RSRP");  // or distance
        
        
}

// 
// eNodeB LtePhy module of PHY Layer
//
simple LtePhyEnb extends LtePhyBase {
        @class("LtePhyEnb");
        
        double targetBler = default(0.001);
        double lambdaMinTh = default(0.02);
        double lambdaMaxTh = default(0.2);
        double lambdaRatioTh = default(20);
}

// 
// eNodeB LtePhy module of PHY Layer with support for D2D
//
simple LtePhyEnbD2D extends LtePhyEnb {
    parameters:
        @class("LtePhyEnbD2D");
        bool enableD2DCqiReporting = default(true);
}

// 
// Relay LtePhy module of PHY Layer
//
simple LtePhyRelay extends LtePhyBase {
        @class("LtePhyRelay");
}

simple LtePhyRsu extends LtePhyBase
{
    @class("LtePhyRsu");
}


