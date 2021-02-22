SimuLTE
=======

Cellular V2X protocol stack for discrete event driven simulations.

Dependencies
------------

The current master/head version requires

- OMNeT++ 6.0 and INET 4.3.0
- Facilities layer - Vanetza


Setup
-----

- PATH variable should include omnet bin directory and inet bin directory
- LIBRARY_PATH and LD_LIBRARY_PATH must include the location of the corresponding
shared object libraries 


Features
--------

General

- eNodeB and UE models
- eNodeB based RSU implementation
- Full LTE protocol stack control and user planes
- Sidelink broadcast support
- Uplink and Downlink Unicast and Broadcast

Control plane-RRC

- Finite state machine - RRC_IDLE, RRC_CONN, RRC_INACTIVE states
- Cell search and mode selection
- Sidelink mode switch control 

PDCP-RRC

- Header compression/decompression
- Logical connection establishment  and maintenance 
- Separate pipeline for IP and Non-IP based traffic

RLC

- Multiplexing/Demultiplexing of MAC SDUs
- UM, (AM and TM testing) modes

MAC

- RLC PDUs buffering
- HARQ functionalities (with multi-codeword support)
- Allocation management
- AMC
- Scheduling Policies (MAX C/I, Proportional Fair, DRR)
- Sidelink configutartion - resources and grants

PHY

- Heterogeneous Net (HetNets) support: Macro, micro, pico eNbs
- Channel Feedback management
- Dummy channel model
- Realistic channel model with
  - inter-cell interference
  - path-loss
  - fast fading
  - shadowing 
  - (an)isotropic antennas
  - Sidelink resource allocation - configuration of CSR pools

Other

- X2 communication support
- X2-based handover
- Device-to-device communications
- Support for vehicular mobility
- Sidelink mode 3 and mode 4 support (in-coverage and out-of-coverage)

Applications

- Voice-over-IP (VoIP)
- Constant Bit Rate (CBR)
- Trace-based Video-on-demand traffic
- Non-IP based CAMs
- Event driven Alert Messages


Limitations
-----------

- FDD only (TDD not supported)
- no EPS bearer support – note: a similar concept, "connections", has 
  been implemented, but they are neither dynamic nor statically 
  configurable via some config file
- Implementation of only relevant MIB and SIB in the control plane
- radio bearers not implemented, not even statically configured radio 
  bearers (dynamically allocating bearers would need the RRC protocol, 
  which is Control Plane so not implemented)
  
  


