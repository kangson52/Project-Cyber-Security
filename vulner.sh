#!/bin/bash



 echo -e "${GREEN}VULNER - Vulnerability Scanner${NC}"
 echo -e "${YELLOW}Name: Tann Kangson${NC}"
  echo -e "${YELLOW}Student Code: S12${NC}"
 echo -e "${YELLOW}Class Code: TCI-2409-Cambodia-II${NC}"
 echo -e "${YELLOW}Lecturer: Harshit Katiyar${NC}"

# Function to validate IP/CIDR input
validate_network_input() {
    local network=$1
    if [[ $network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$ ]]; then
        return 0
    else
        echo -e "Invalid network format. Please use CIDR notation (e.g., 192.168.1.0/24)."
        return 1
    fi
}

# Function to validate directory name
validate_directory_name() {
    local dir_name=$1
    if [[ -z $dir_name ]]; then
        echo "Directory name cannot be empty."
        return 1
    elif [[ -d $dir_name ]]; then
        echo "Directory '$dir_name' already exists. Please choose a different name."
        return 1
    else
        return 0
    fi
}

# Function to perform a basic scan with TCP/UDP choice
basic_scan() {
    local network=$1
    local output_dir=$2
    echo "Choose scan type for Basic Scan:"
    echo "1. TCP"
    echo "2. UDP"
    echo "3. Both TCP and UDP"
    while true; do
        read -p "Enter your choice (1, 2, or 3): " scan_choice
        case $scan_choice in
            1)
                echo "Starting Basic TCP Scan..."
                nmap -sS -sV -oA "$output_dir/basic_scan_tcp" "$network"
                echo "Basic TCP Scan completed. Results saved in $output_dir/basic_scan_tcp."
                break
                ;;
            2)
                echo "Starting Basic UDP Scan..."
                nmap -sU -sV -oA "$output_dir/basic_scan_udp" "$network"
                echo "Basic UDP Scan completed. Results saved in $output_dir/basic_scan_udp."
                break
                ;;
            3)
                echo "Starting Basic TCP and UDP Scan..."
                nmap -sS -sU -sV -oA "$output_dir/basic_scan_tcp_udp" "$network"
                echo "Basic TCP and UDP Scan completed. Results saved in $output_dir/basic_scan_tcp_udp."
                break
                ;;
            *)
                echo "Invalid choice. Please enter 1, 2, or 3."
                ;;
        esac
    done
}

# Function to perform a full scan with TCP/UDP choice
full_scan() {
    local network=$1
    local output_dir=$2
    echo "Choose scan type for Full Scan:"
    echo "1. TCP"
    echo "2. UDP"
    echo "3. Both TCP and UDP"
    while true; do
        read -p "Enter your choice (1, 2, or 3): " scan_choice
        case $scan_choice in
            1)
                echo "Starting Full TCP Scan..."
                nmap -sS -sV --script=vuln -oA "$output_dir/full_scan_tcp" "$network"
                echo "Full TCP Scan completed. Results saved in $output_dir/full_scan_tcp."
                break
                ;;
            2)
                echo "Starting Full UDP Scan..."
                nmap -sU -sV --script=vuln -oA "$output_dir/full_scan_udp" "$network"
                echo "Full UDP Scan completed. Results saved in $output_dir/full_scan_udp."
                break
                ;;
            3)
                echo "Starting Full TCP and UDP Scan..."
                nmap -sS -sU -sV --script=vuln -oA "$output_dir/full_scan_tcp_udp" "$network"
                echo "Full TCP and UDP Scan completed. Results saved in $output_dir/full_scan_tcp_udp."
                break
                ;;
            *)
                echo "Invalid choice. Please enter 1, 2, or 3."
                ;;
        esac
    done
}

# Function to map usernames to IP addresses and check weak credentials
map_username_to_ip() {
    local network=$1
    local output_dir=$2
    local username=$3
    local password_list=$4
    echo "Mapping username '$username' to IP addresses in the network..."
    echo "Scanning for SSH, RDP, FTP, and TELNET services..."

    # Perform a service scan to identify open ports
    nmap -p 22,3389,21,23 -oG - "$network" | awk '/open/ {print $2}' > "$output_dir/active_hosts.txt"

    # Check each active host for the username and attempt to crack passwords
    while read -r ip; do
        echo "Checking $ip for username '$username'..."
        
        # Attempt to crack SSH password
        echo "Attempting to crack SSH password for $username on $ip..."
        hydra -l "$username" -P "$password_list" -t 4 -vV -e ns -s 22 "$ip" ssh -o "$output_dir/weak_credentials_ssh_22.txt"
        
        # Check if a password was found
        if grep -q "login:" "$output_dir/weak_credentials_ssh_22.txt"; then
            echo "Password cracked for SSH on $ip."
            return 0
        else
            echo "No weak credentials found for SSH on $ip."
        fi
    done < "$output_dir/active_hosts.txt"

    echo "Username '$username' not found on any active hosts."
    return 1
}

# Function to check for weak credentials for a specific service and port
check_weak_credentials_single_user() {
    local output_dir=$1
    local password_list=$2
    local username=$3
    local target_ip=$4
    local service=$5
    local port=$6

    echo "Checking for weak credentials for username: $username on IP: $target_ip for service: $service (port: $port)..."

    # Run Hydra for the specific service and port
    echo "Starting Hydra for $service on port $port..."
    hydra -l "$username" -P "$password_list" -t 4 -vV -e ns -s "$port" "$target_ip" "$service" -o "$output_dir/weak_credentials_${service}_${port}.txt"

    echo "Weak credentials check for $service (port: $port) completed. Results saved in $output_dir/weak_credentials_${service}_${port}.txt."
}

# Function to check for weak credentials using a username list
check_weak_credentials_user_list() {
    local network=$1
    local output_dir=$2
    local password_list=$3
    local user_list=$4
    echo "Checking for weak credentials using username list..."

    # Define services and their default ports
    declare -A services=(
        ["ssh"]="22"
        ["rdp"]="3389"
        ["ftp"]="21"
        ["telnet"]="23"
    )

    # Loop through each service and port
    for service in "${!services[@]}"; do
        local port="${services[$service]}"
        echo "Checking $service on port $port..."
        
        # Run Hydra for the specific service and port
        hydra -L "$user_list" -P "$password_list" -t 4 -vV -e ns -s "$port" "$network" "$service" -o "$output_dir/weak_credentials_${service}_${port}.txt"
        
        # Check if any credentials were found
        if grep -q "login:" "$output_dir/weak_credentials_${service}_${port}.txt"; then
            echo "Weak credentials found for $service on port $port."
        else
            echo "No weak credentials found for $service on port $port."
        fi
    done

    echo "Weak credentials check completed. Results saved in $output_dir."
}

# Function to map vulnerabilities
map_vulnerabilities() {
    local network=$1
    local output_dir=$2
    echo "Mapping vulnerabilities..."
    searchsploit --nmap "$output_dir/full_scan_tcp.xml" > "$output_dir/vulnerabilities_tcp.txt"
    searchsploit --nmap "$output_dir/full_scan_udp.xml" > "$output_dir/vulnerabilities_udp.txt"
    echo "Vulnerability mapping completed. Results saved in $output_dir."
}

# Function to log results and allow searching
log_results() {
    local output_dir=$1
    echo "Scan results:"
    cat "$output_dir"/*.txt
    read -p "Enter a keyword to search in the results (or press Enter to skip): " keyword
    if [[ -n $keyword ]]; then
        grep -i "$keyword" "$output_dir"/*.txt
    fi
}

# Function to save results into a Zip file
save_results() {
    local output_dir=$1
    echo "Saving results to a Zip file..."
    zip -r "$output_dir.zip" "$output_dir"
    echo "Results saved in $output_dir.zip."
}

# Main script
echo "Welcome to the Network Scanner!"

# 1.1 Get from the user a network to scan
while true; do
    read -p "Enter the network to scan (e.g., 192.168.1.0/24): " network
    if validate_network_input "$network"; then
        break
    fi
done

# 1.2 Get from the user a name for the output directory
while true; do
    read -p "Enter a name for the output directory: " output_dir
    if validate_directory_name "$output_dir"; then
        mkdir -p "$output_dir"
        break
    fi
done

# 1.3 Allow the user to choose 'Basic' or 'Full'
echo "Choose scan type:"
echo "1. Basic"
echo "2. Full"
while true; do
    read -p "Enter your choice (1 or 2): " scan_type
    case $scan_type in
        1)
            basic_scan "$network" "$output_dir"
            break
            ;;
        2)
            full_scan "$network" "$output_dir"
            break
            ;;
        *)
            echo "Invalid choice. Please enter 1 or 2."
            ;;
    esac
done

# 2. Weak Credentials
read -p "Do you want to check for weak credentials? (y/n): " check_credentials
if [[ $check_credentials == "y" ]]; then
    read -p "Use built-in password list or provide your own? (builtin/custom): " password_list_choice
    if [[ $password_list_choice == "builtin" ]]; then
        password_list="/usr/share/john/password.lst"
    elif [[ $password_list_choice == "custom" ]]; then
        read -p "Enter the path to your password list: " password_list
        if [[ ! -f $password_list ]]; then
            echo "File not found. Using built-in password list."
            password_list="password.lst"
        fi
    else
        echo "Invalid choice. Using built-in password list."
        password_list="password.lst"
    fi

    read -p "Do you want to use a single username or a username list? (single/list): " username_choice
    if [[ $username_choice == "single" ]]; then
        read -p "Enter the username to test: " username
        if map_username_to_ip "$network" "$output_dir" "$username" "$password_list"; then
            echo "Password cracking completed. Check results in $output_dir."
        else
            echo "No weak credentials found."
        fi
    elif [[ $username_choice == "list" ]]; then
        read -p "Enter the path to your username list: " user_list
        if [[ ! -f $user_list ]]; then
            echo "File not found. Please provide a valid username list."
            exit 1
        fi
        check_weak_credentials_user_list "$network" "$output_dir" "$password_list" "$user_list"
    else
        echo "Invalid choice. Exiting."
        exit 1
    fi
fi

# 3. Mapping Vulnerabilities
if [[ $scan_type -eq 2 ]]; then
    map_vulnerabilities "$network" "$output_dir"
fi

# 4. Log Results
log_results "$output_dir"

# 5. Save Results
read -p "Do you want to save the results to a Zip file? (y/n): " save_zip
if [[ $save_zip == "y" ]]; then
    save_results "$output_dir"
fi

echo "Script execution completed."
