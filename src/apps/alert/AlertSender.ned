// 
//                           SimuLTE
// 
// This file is part of a software released under the license included in file
// "license.pdf". This license can be also found at http://www.ltesimulator.com/
// The above file and the present reference are part of the software itself, 
// and cannot be removed from it.
// 

package lte.apps.alert;

import inet.applications.contract.IUDPApp;

simple AlertSender like IUDPApp
{
    parameters:
        int localPort = default(-1);
        int destPort = default(3000);
        string destAddress;
        int packetSize = default(100);
        double period @unit("s") = default(0.1s);
        double startTime @unit("s") = default(0s);
        double stopTime @unit("s") = default(0s); // 0 means "never stops" 
        string interfaceTableModule;
        int pktId = default(1000);  
        
        //Statistics collection     
        @signal[numberAlertGenerated];
		@statistic[numberAlertGenerated](title="Number of Alert messages generated"; source="numberAlertGenerated"; record=vector,stats);
		@signal[transmittedPacketId];
		@statistic[transmittedPacketId](title="Number of Alert messages generated"; source="transmittedPacketId"; record=vector,stats);
        @display("i=block/source");
    gates:
        output udpOut;
        input udpIn;
}
