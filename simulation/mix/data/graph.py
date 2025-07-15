import json

SWITCH_LIST = [9, 10, 11, 12]

def sim_pkt_queue(flows, pktnums, queuedepths):
    flownum = len(flows)
    if flownum == 0:
        return
    ptrs = [0] * flownum
    pkt_list = []
    pkt_waitfor = []
    degree = {}

    for flow_id in range(flownum):
        degree[flows[flow_id]] = 0
        pkt_waitfor.append([])
        for flow_id1 in range(flownum):
            pkt_waitfor[flow_id].append(0)
    
    while True:
        rela_ptrs = [ ptr/pktnum for ptr, pktnum in zip(ptrs, pktnums)]
        if(min(rela_ptrs) >= 1):
            break
        max_idx = rela_ptrs.index(min(rela_ptrs))
        ptrs[max_idx] += 1
        pkt_list.append(max_idx)

    for pkt_id in range(len(pkt_list)):
        queuedepth = queuedepths[pkt_list[pkt_id]]
        for i in range(1, queuedepth + 1):
            if pkt_id - i < 0:
                break
            pkt_waitfor[pkt_list[pkt_id]][pkt_list[pkt_id - i]] += 1

    for flow_idx in range(flownum):
        for flow_idx1 in range(flownum):
            pkt_waitfor[flow_idx][flow_idx1] = round(pkt_waitfor[flow_idx][flow_idx1] / pktnums[flow_idx], 1)
    pkt_waitfor = [dict(zip(flows, pkt_waitfor[flow_idx])) for flow_idx in range(flownum)]
    pkt_waitfor = dict(zip(flows, pkt_waitfor))

    for flow in flows:
        for flow1 in flows:
            degree[flow] -= pkt_waitfor[flow][flow1]
            degree[flow1] += pkt_waitfor[flow][flow1]

    return degree

def parse_telemetry(switch_dict, switch_list):
    for swicth_id in switch_list:
        f = open("telemetry_"+str(swicth_id)+".txt", 'r')
        lines = f.readlines()
        f.close()

        switch_dict[str(swicth_id)] = {}
        line_idx = 0
        while line_idx < len(lines):
            line = lines[line_idx]
            
            if line.startswith("time"):
                time = line.split()[1]
                switch_dict[str(swicth_id)][time] = {"epoch_now":{},"epoch_last":{}}
                porttelemetry = {"epoch_now":{},"epoch_last":{}}
                trafficmeter = {}
                inport = -1
                teleflag = False
                polling = False
                port = "0"
                epoch = "epoch_now"

            elif line.startswith("end"):
                if inport != -1:
                    switch_dict[str(swicth_id)][time]["inport"] = inport
                for epoch in ["epoch_now", "epoch_last"]:
                    if switch_dict[str(swicth_id)][time][epoch] != {} and polling == False:
                        for key in porttelemetry[epoch].keys():
                            if sum(trafficmeter.values()) == 0:
                                porttelemetry[epoch][key] = 0
                            else:
                                porttelemetry[epoch][key] = porttelemetry[epoch][key] * trafficmeter[key] / sum(trafficmeter.values())
                        switch_dict[str(swicth_id)][time][epoch]["p2p_weight"] = porttelemetry[epoch]
                
            elif line.startswith("polling"):
                switch_dict[str(swicth_id)][time]["type"] = "flow_trace"
                polling = True
            elif line.startswith("signal"):
                switch_dict[str(swicth_id)][time]["type"] = "pfc_trace"
                polling = False
            elif line.startswith("epoch"):
                epoch = "epoch_"+line.split()[1]
            elif teleflag and line == '\n':
                teleflag = False
                degrees = sim_pkt_queue(flows, pktnums, queuedepths)
                if degrees is not None:
                    switch_dict[str(swicth_id)][time][epoch][port]["p2f_weight"] = degrees
            elif line.startswith("flow telemetry"):
                flows = []
                pktnums = []
                queuedepths = []
                switch_dict[str(swicth_id)][time][epoch][port]["f2p_weight"] = {}
                port = line.split()[-1]
                line_idx += 1
                teleflag = True
            elif line.startswith("port telemetry"):
                port = line[:-1].split()[-1]
                pktnum = int(lines[line_idx+2].split()[2])
                qdepth = int(lines[line_idx+2].split()[0])
                paused = int(lines[line_idx+2].split()[1])
                switch_dict[str(swicth_id)][time][epoch][port] = {}
                switch_dict[str(swicth_id)][time][epoch][port]["paused_pkt"] = paused
                if pktnum == 0:
                    porttelemetry[epoch][line[:-1].split()[-1]] = 0
                else:
                    porttelemetry[epoch][line[:-1].split()[-1]] = qdepth / pktnum
            elif line.startswith("traffic meter form port"):
                port = line[:-1].split()[-1]
                trafficmeter[port] = int(lines[line_idx+2][:-1])
                inport = line[:-1].split()[4]
            elif teleflag:
                flow = line.split()[1]+"->"+line.split()[2]
                pktnum = int(line.split()[8])
                paused = int(line.split()[10])
                flows.append(flow)
                pktnums.append(pktnum)
                switch_dict[str(swicth_id)][time][epoch][port]["f2p_weight"][flow] = paused
                if (int(line.split()[8])-int(line.split()[10])) == 0:
                    queuedepths.append(0)
                else:
                    queuedepths.append(int(int(line.split()[9]) / (int(line.split()[8])-int(line.split()[10]))))

            line_idx += 1

def main():
    switch_list = SWITCH_LIST
    switch_dict = {}

    parse_telemetry(switch_dict, switch_list)

    for switch in switch_dict.keys():
        time_list = list(switch_dict[switch].keys())
        for time_idx in range(len(time_list) - 1):
            if int(time_list[time_idx + 1]) - int(time_list[time_idx]) < 50000:
                switch_dict[switch].pop(time_list[time_idx+1])

    with open('telemetry.json', 'w') as f:
        json.dump(switch_dict, f)

if __name__ == "__main__":
    main()