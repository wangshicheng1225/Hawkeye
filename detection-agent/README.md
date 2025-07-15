# detection agent

The detection agent that estimating flow RTT and send polling packet to network, built with DOCA PCC.

## Prerequisites

1. two NVIDIA BlueField 3 DPU and DOCA>=2.7 is required.
2. execute `mlxconfig -y -d /dev/mst/<your device> set USER_PROGRAMMABLE_CC=1` on **both** RP and NP and do a BlueField system reboot to enable PCC.

## Build and run

### RP

1. execute `./rebuild.sh` to build the app.
2. execute `sudo ./builddir/detection_agent -d <ibv_name>` to run the RP function.

### NP

1. execute `./rebuild.sh` to build the app.
2. execute `sudo ./builddir/detection_agent -d <ibv_name> -np-nt` to run the NP function.

### Notifications

1. It works when all devices are in a same local network(L2 broadcast domain), since the agent use SIOCGARP to query target MAC address.