
# port list at different pipeline
port_list = ["10/0", "11/0", "12/0", "16/0", "28/0", "29/0", "30/0", "31/0", "32/0"]
# port and corresponding dev_port list for logic switch1
port_list_a = ["10/0", "11/0", "12/0", "16/0"]
dev_port_list_a = [52, 44, 36, 4]
# port and devport list for logic switch 2
port_list_b = ["28/0", "29/0", "30/0", "31/0", "32/0"]
dev_port_list_b = [164, 148, 156, 132, 140]

# forwarding table list
# emulate multiple logic switches by using 2-D forwarding (ingress port, dst IP) -> egress port
# it is not related to hawkeye logic
# covert to IP forwarding if no need in emulating tofino into multiple logic switches
forward_list = [
    (44, "172.17.1.106", 36),
    (44, "172.17.2.103", 52),
    (44, "172.17.3.104", 52),
    (44, "172.17.2.108", 52),
    (44, "172.17.3.109", 52),
    (36, "172.17.1.101", 44),
    (36, "172.17.2.103", 52),
    (36, "172.17.3.104", 52),
    (36, "172.17.2.108", 52),
    (36, "172.17.3.109", 52),
    (52, "172.17.1.101", 44),
    (52, "172.17.1.106", 36),
    (132, "172.17.3.104", 148),
    (132, "172.17.2.108", 140),
    (132, "172.17.3.109", 156),
    (132, "172.17.1.101", 164),
    (132, "172.17.1.106", 164),
    (140, "172.17.2.103", 132),
    (140, "172.17.3.104", 148),
    (140, "172.17.3.109", 156),
    (140, "172.17.1.101", 164),
    (140, "172.17.1.106", 164),
    (148, "172.17.2.103", 132),
    (148, "172.17.2.108", 140),
    (148, "172.17.3.109", 156),
    (148, "172.17.1.101", 164),
    (148, "172.17.1.106", 164),
    (156, "172.17.2.103", 132),
    (156, "172.17.3.104", 148),
    (156, "172.17.2.108", 140),
    (156, "172.17.1.101", 164),
    (156, "172.17.1.106", 164),
    (164, "172.17.2.103", 132),
    (164, "172.17.2.108", 140),
    (164, "172.17.3.104", 148),
    (164, "172.17.3.109", 156),
]

# polling multicast group ID at each logic switch
# POLLING_MC_GID_A = 126
# POLLING_MC_GID_B = 127
POLLING_MC_GID_A = "POLLING_MC_GID_A" 
POLLING_MC_GID_B = "POLLING_MC_GID_B" 


forward_polling_list = []

for entry in forward_list:
    dev_port, ip_address, target_dev_port = entry
    
    forward_polling_list.append((1, dev_port, ip_address, "ai_unicast_polling", target_dev_port, 0))
    
    if dev_port in dev_port_list_a:
        polling_mc_gid = POLLING_MC_GID_A
    elif dev_port in dev_port_list_b:
        polling_mc_gid = POLLING_MC_GID_B
    else:
        polling_mc_gid = 0  
    
    forward_polling_list.append((3, dev_port, ip_address, "ai_broadcast_polling", target_dev_port, dev_port))

for dev_port in	dev_port_list_a:
	forward_polling_list.append((2, dev_port, '0.0.0.0', "ai_broadcast_polling", 511, dev_port))

for dev_port in	dev_port_list_b:
	forward_polling_list.append((2, dev_port, '0.0.0.0', "ai_broadcast_polling", 511, dev_port))

# print("const forward_polling_entry_t FORWARD_POLLING_LIST[] = {")
# for entry in forward_polling_list:
#     print(f"    {{0x{entry[0]:X}, {entry[1]}, \"{entry[2]}\", \"{entry[3]}\", {entry[4]}, {entry[5]}}},")
# print("};")
print("const forward_polling_entry_t FORWARD_POLLING_LIST[] = {")
for entry in forward_polling_list:
    # print("    {{0x{:X}, {}, \"{}\", \"{}\", {}, {}}},".format(entry[0], entry[1], entry[2], entry[3], entry[4], entry[5]))
    print("    {{{}, {}, \"{}\", \"{}\", {}, {}}},".format(entry[0], entry[1], entry[2], entry[3], entry[4], entry[5]))
print("};")

