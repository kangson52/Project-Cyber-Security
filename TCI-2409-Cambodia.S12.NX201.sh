#!/bin/bash

IP=$(curl -s https://api.ipify.org)


function install()
{
	applications=("curl" "openssh-server" "sshpass" "nmap" "whois" "geoip-bin")

	for app in "${applications[@]}"; do
		if command -v "$app" &> /dev/null; then
			echo "$app is already installed."
		else
			echo "$app is not installed. Installing now..."
			sudo apt install "$app" -y 
		fi
	done
}

function check()
{
	Country=$(whois $IP | grep -i country)
	if [ "$Country" ]
	then 
		echo "You are not anonymous !"
	else 
		echo "You are anonymous - spoofed country: $(geoiplookup $IP | awk '{print $4}')"
	fi
}

function RM()
{
	echo "::::Make Connection to SSH::::"
	read -p "=> Enter username: " USERNAME
	read -p "=> Enter remote IP: " REMOTEIP
	read -p "=> Enter password: " PASSWORD
	sshpass -p "$PASSWORD" ssh $USERNAME@$REMOTEIP 'ls; whoami'
}

function Scan()
{
	echo "::::Start to Scan any Domain::::"
	read -p "[*] Enter a domain to scan : " DMN
	Log
	scan_ip=$(dig +short $DMN)
	country=$(geoiplookup $DMN | awk '{print $5}')
	whois $DMN >> NR.log
	nmap -Pn -F $DMN >> NR.log
	cat NR.log
}
 
function Log()
{
	echo "$(date) - inspecting $DMN " > NR.log
}	

install
check
RM
Scan
