# Step-by-step kernel-level observation for AF_XDP pipeline

set -e

# 1. Veth/Netns Setup

echo "\n[1] Network namespaces:"
ip netns list

echo "\n[1] Veth interfaces:"
ip link show | grep veth

echo "\n[1] IP addresses in ns1 and ns2:"
ip netns exec ns1 ip addr show
ip netns exec ns2 ip addr show

# 2. XDP Program Attachment

echo "\n[2] XDP status on veth0:"
ip netns exec ns1 ip link show veth0

echo "\n[2] Loaded BPF programs:"
bpftool prog show

echo "\n[2] BPF maps:"
bpftool map show

# 3. AF_XDP Socket Setup

echo "\n[3] XSKMAP contents:"
bpftool map dump name xsks_map

# 4. Traffic Generation & Kernel Observation

echo "\n[4] tcpdump on veth0 (ns1):"
ip netns exec ns1 tcpdump -i veth0 udp port 4242 -vv -c 5

echo "\n[4] tcpdump on veth1 (ns2):"
ip netns exec ns2 tcpdump -i veth1 udp port 4242 -vv -c 5

echo "\n[4] RX/TX stats for veth0 and veth1:"
ip -s link show veth0
ip -s link show veth1

echo "\n[4] Driver statistics for veth0 and veth1:"
ethtool -S veth0 || echo "ethtool stats not available for veth0"
ethtool -S veth1 || echo "ethtool stats not available for veth1"

# 5. Forwarding & XDP Debugging

echo "\n[5] BPF program trace logs:"
bpftool prog tracelog || echo "bpftool tracelog not available"

echo "\n[5] Kernel messages (dmesg):"
dmesg | tail

# 6. Map and Program Status

echo "\n[6] XDP program status on interfaces:"
bpftool net show

echo "\n[6] All BPF objects:"
bpftool object show

echo "\nObservation steps complete."
