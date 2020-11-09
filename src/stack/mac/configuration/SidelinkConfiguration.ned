//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package lte.stack.mac.configuration;

//
// TODO auto-generated module
//
simple SidelinkConfiguration
{
    parameters:
        
        @class("SidelinkConfiguration");
        
        //# TODO: Change this to use xmldoc to fill in these params as it's more complex than this.
        xml txConfig;
        int restrictResourceReservationperiod = default(1);
        int maximumLatency = default(100);
        int minSubchannelNumberPSSCH = default(1);
        int maxSubchannelNumberPSSCH = default(10);
        int minMCSPSSCH = default(1);
        int maxMCSPSSCH = default(28);
        int allowedRetxNumberPSSCH = default(0);
        int numSubchannels = default(5);
        int subchannelSize = default(5);
        int reselectAfter = default(1);
        double probResourceKeep = default(0.4);
        bool useCBR = default(false);
        bool packetDropping = default(false);
        int resourceReselectionCounter = default(5);
        bool usePreconfiguredTxParams = default(false);
        
        // Signals 
        //
        // Must haves:
        // Grant break due to no time
        // Grant break due to no large enough MCS
        // Selected MCS
        // Selected number of subchannels
        // Packet size on break 
        // Maximum capacity on grant break
        
        @signal[grantStartTime];
        @statistic[grantStartTime](title="Grant StartTime"; source="grantStartTime"; record=sum,vector);
        @signal[grantBreak];
        @statistic[grantBreak](title="Total Number of Grant breaks"; source="grantBreak"; record=sum,vector);
        @signal[grantBreakTiming];
        @statistic[grantBreakTiming](title="Total number of Grant breaks due to not meeting time requirements"; source="grantBreakTiming"; record=sum,vector);
        @signal[grantBreakSize];
        @statistic[grantBreakSize](title="Total Number of Grant breaks due to not having enough capacity" ; source="grantBreakSize"; record=count,sum,vector);
        @signal[droppedTimeout];
        @statistic[droppedTimeout](title="Total Number of packets dropped due to a timeout" ; source="droppedTimeout"; record=sum,vector);
        @signal[grantBreakMissedTrans];
        @statistic[grantBreakMissedTrans](title="Total grant breaks due to missed transmissions"; source="grantBreakMissedTrans"; record=sum,vector);
        @signal[missedTransmission];
        @statistic[missedTransmission](title="Total Missed transmissions"; source="missedTransmission"; record=sum,vector);
        @signal[selectedMCS];
        @statistic[selectedMCS](title="MCS selected for transmission"; source="selectedMCS"; record=mean,vector);
        @signal[selectedNumSubchannels];
        @statistic[selectedNumSubchannels](title="SelectedNumSubchannels"; source="selectedNumSubchannels"; record=mean,vector);
        @signal[selectedSubchannelIndex];
        @statistic[selectedSubchannelIndex](title="SelectedSubchannelIndex"; source="selectedSubchannelIndex"; record=mean,vector);
        @signal[maximumCapacity];
        @statistic[maximumCapacity](title="Maximum capacity of grant"; source="maximumCapacity"; record=mean,vector);
        @signal[grantRequest];
        @statistic[grantRequest](title="Total number of requested grants"; source="grantRequest"; record=sum,vector);
        @signal[packetDropDCC];
        @statistic[packetDropDCC](title="Packet drop due to DCC mechanism"; source="packetDropDCC"; record=sum,vector);
        @signal[macNodeID];
        @statistic[macNodeID](title="Reports Mac NodeID to allow for trans to nodeID"; source="macNodeID"; record=vector);
        @signal[dataPDUSizeTransmitted];
        @statistic[dataPDUSizeTransmitted](title="PDU size ready for transmission across channel"; unit="bytes"; source="dataPDUSizeTransmitted"; record=mean,vector,stats);
        
        
        
}
