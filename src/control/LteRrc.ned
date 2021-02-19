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

package lte.control;

import lte.control.ControlPlane;
//
// TODO auto-generated module
//
simple LteRrcBase like ControlPlane
{
    parameters:
        string nodeType;
        
        //Timers
        @signal[detectionLatency];
        @statistic[detectionLatency](title="Detection Latency"; source="detectionLatency"; record=vector,stats);
        
        
    gates:
        input control_IN @directIn;
        inout PDCP_control;
        inout TM_control;     
        inout AM_control; 
        inout UM_control; 
        inout PHY_control;
        inout MAC_control;
        
        
        
}

simple LteRrcUe extends LteRrcBase{
    parameters:
        @class("LteRrcUe");
        
        
        
}

simple LteRrcEnb extends LteRrcBase{
    parameters:
        @class("LteRrcEnb");
        
}

simple LteRrcRsuEnb extends LteRrcBase{
    parameters:
        @class("LteRrcRsuEnb");
}

