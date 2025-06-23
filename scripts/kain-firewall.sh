#!/bin/bash
#
# Kain Linux Kernel - Basic Firewall Configuration
# This script sets up a basic but secure firewall using iptables
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Kain Linux Firewall Configuration${NC}"
echo "================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Please run as root${NC}"
    exit 1
fi

# Check if iptables module is loaded
if ! lsmod | grep -q ip_tables; then
    echo -e "${YELLOW}Loading iptables modules...${NC}"
    modprobe ip_tables
    modprobe ip_conntrack
    modprobe iptable_filter
    modprobe iptable_nat
    modprobe iptable_mangle
fi

# Function to setup basic firewall rules
setup_firewall() {
    echo -e "${YELLOW}Setting up firewall rules...${NC}"
    
    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established and related connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    
    # Protection against common attacks
    # Syn-flood protection
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
    
    # Drop fragmented packets
    iptables -A INPUT -f -j DROP
    
    # Drop XMAS packets
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    
    # Drop NULL packets
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    
    # Block common attack ports
    iptables -A INPUT -p tcp --dport 135:139 -j DROP
    iptables -A INPUT -p tcp --dport 445 -j DROP
    iptables -A INPUT -p udp --dport 135:139 -j DROP
    
    # Rate limiting for SSH (if needed)
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
    
    # Allow SSH (adjust port as needed)
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
    
    # Allow HTTP/HTTPS (uncomment if needed)
    # iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
    # iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
    
    # Allow ping (ICMP echo-request) with rate limiting
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 2 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    
    # Log dropped packets (uncomment for debugging)
    # iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-dropped: " --log-level 7
    
    echo -e "${GREEN}Firewall rules applied successfully!${NC}"
}

# Function to show current rules
show_rules() {
    echo -e "\n${YELLOW}Current firewall rules:${NC}"
    echo "======================="
    iptables -L -n -v
}

# Function to save rules
save_rules() {
    echo -e "\n${YELLOW}Saving firewall rules...${NC}"
    
    # Different methods for different distros
    if [ -f /etc/debian_version ]; then
        iptables-save > /etc/iptables/rules.v4
        echo -e "${GREEN}Rules saved to /etc/iptables/rules.v4${NC}"
    elif [ -f /etc/redhat-release ]; then
        service iptables save
        echo -e "${GREEN}Rules saved via service${NC}"
    else
        iptables-save > /etc/sysconfig/iptables
        echo -e "${GREEN}Rules saved to /etc/sysconfig/iptables${NC}"
    fi
}

# Function to enable on boot
enable_on_boot() {
    echo -e "\n${YELLOW}Enabling firewall on boot...${NC}"
    
    # Create systemd service
    cat > /etc/systemd/system/kain-firewall.service << EOF
[Unit]
Description=Kain Linux Firewall
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash $0 start
ExecStop=/bin/bash $0 stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable kain-firewall.service
    echo -e "${GREEN}Firewall enabled on boot${NC}"
}

# Function to stop firewall
stop_firewall() {
    echo -e "${YELLOW}Stopping firewall...${NC}"
    iptables -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    echo -e "${GREEN}Firewall stopped${NC}"
}

# Main script logic
case "$1" in
    start)
        setup_firewall
        show_rules
        ;;
    stop)
        stop_firewall
        ;;
    restart)
        stop_firewall
        setup_firewall
        show_rules
        ;;
    status)
        show_rules
        ;;
    save)
        save_rules
        ;;
    enable)
        setup_firewall
        save_rules
        enable_on_boot
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|save|enable}"
        echo ""
        echo "  start   - Start firewall with default rules"
        echo "  stop    - Stop firewall (flush all rules)"
        echo "  restart - Restart firewall"
        echo "  status  - Show current rules"
        echo "  save    - Save current rules"
        echo "  enable  - Start firewall, save rules, and enable on boot"
        exit 1
        ;;
esac

exit 0