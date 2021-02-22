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

package lte.stack.phy.resources;

//
// TODO auto-generated module
//
simple SidelinkResourceAllocation
{
        bool adjacencyPSCCHPSSCH = default(true);
        int pStep = default(100); 
        int numSubchannels = default(5); // {n4, n5, n6, n8, n9, n10, n12, n15, n16, n18, n20, n25, n30, n48, n50, n72, n75, n96, n100}
        int subchannelSize = default(5); //{n1, n3, n5, n10, n15, n20}
        int subChRBStart = default(0);
        int selectionWindowStartingSubframe = default(1);
        int shapeFactor = default(6);
        int thresholdRSSI = default(22);
        double d2dTxPower =default(26);
        int numberSubcarriersperPRB = default(12);
        int numberSymbolsPerSlot=default(7);
        int bitsPerSymbolQPSK=default(2);
        @signal[numberSubchannels];
		@statistic[numberSubchannels](title="Number of subchannels"; source="numberSubchannels"; record=sum,vector);
		@signal[totalCSR];
		@statistic[totalCSR](title="Number of CSRs"; source="totalCSR"; record=sum,vector);
		@signal[syncLatency];
		@statistic[syncLatency](title="Synchronization latency"; source="syncLatency"; record=vector,stats);
		@signal[resourceAllocationLatency];
		@statistic[resourceAllocationLatency](title="Resourcelatency"; source="resourceAllocationLatency"; record=vector,stats);
        @signal[configurationLatency];
		@statistic[configurationLatency](title="Configurationlatency"; source="configurationLatency"; record=vector,stats);
        @signal[halfDuplex];
        @statistic[halfDuplex](title="Half duplex error"; unit=""; source="halfDuplex"; record=mean,vector,stats);
        @signal[packetCollisionMode4];
        @statistic[packetCollisionMode4](title="packet collision in mode 4"; unit=""; source="packetCollisionMode4"; record=mean,vector,stats);
        
}
