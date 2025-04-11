#!/bin/bash
# Secure iptables configuration for SMB/Shell server in competition

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies (deny all by default)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH only from specific trusted sources
# Allow from Scoring Engine
iptables -A INPUT -p tcp --dport 22 -s 172.18.0.0/16 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -s 172.18.0.0/16 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp --dport 22 -s 172.18.0.0/16 -m conntrack --ctstate NEW -j ACCEPT

# Allow SSH from internal team network
iptables -A INPUT -p tcp --dport 22 -s 192.168.12.0/24 -j ACCEPT

# Allow Samba (SMB) only from scoring engine and team network
iptables -A INPUT -p tcp --dport 445 -s 172.18.0.0/16 -j ACCEPT  # External network (for scoring)
iptables -A INPUT -p tcp --dport 445 -s 192.168.12.0/24 -j ACCEPT # Internal team network

# Block invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Block common attack vectors
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP               # NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP                # XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP        # Malformed packets
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP # Malformed packets
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP        # SYN-RST packets
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP        # SYN-FIN packets

# Rate limit ICMP to prevent flooding
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Allow DHCP client (if your server gets an IP via DHCP)
iptables -A INPUT -p udp --dport 68 --sport 67 -j ACCEPT

# Log and drop all other incoming traffic
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A INPUT -j DROP

# Save the rules
iptables-save > /etc/iptables/rules.v4
