#!/bin/bash

# 1. Identify the system's public IP.
echo "Public IP:"
curl -s ifconfig.me

# 2. Identify the private IP address assigned to the system's network interface.
echo -e "\nPrivate IP:"
ip addr show | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}'

# 3. Display the MAC address (masking sensitive portions for security).
echo -e "\nMAC Address (Masked):"
ip link show | awk '/ether/ {print substr($2, 1, 9)"XX:XX:XX"}'

# 4. Display the percentage of CPU usage for the top 5 processes.
echo -e "\nTop 5 CPU-consuming processes:"
top -b -n1 | head -n 12 | tail -n 5

# 5. Display memory usage statistics: total and available memory.
echo -e "\nMemory Usage (Total and Available):"
free -h | awk '/^Mem:/ {print "Total: "$2", Used: "$3", Free: "$4}'

#6. List active system services with their status.
echo -e "\nActive Services:"
systemctl list-units --type=service --state=active

# 7. Locate the Top 10 Largest Files in /home.
echo -e "\nTop 10 Largest Files in /home:"
find /home -type f -exec du -h {} + 2>/dev/null | sort -rh | head -n 10
